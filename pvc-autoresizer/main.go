package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apiserver/pkg/cel/library"
	"sigs.k8s.io/yaml"
)

const (
	denyPrefix = "deny:"
)

var (
	//go:embed expression.cel
	expression string
	//go:embed metrics.json
	metricsJson []byte
	//go:embed pvcs.yaml
	pvcsYaml []byte
	//go:embed scs.yaml
	scsYaml []byte
)

type VolumeStats struct {
	AvailableBytes     int64 `json:"availableBytes"`
	CapacityBytes      int64 `json:"capacityBytes"`
	AvailableInodeSize int64 `json:"availableInodeSize"`
	CapacityInodeSize  int64 `json:"capacityInodeSize"`
}

func main() {
	// setup CEL
	env, err := cel.NewEnv(
		// https://kubernetes.io/docs/reference/using-api/cel/#kubernetes-quantity-library
		library.Quantity(),

		// defined types by protobuf
		/*
			Kubernetes API types are defined by protobuf but are not protobuf generated types.
			K8s の API は protobuf で定義されているが、protobuf 生成された型ではないらしい。エラーになる。
			https://christina04.hatenablog.com/entry/use-custom-variable-in-cel
			https://codelabs.developers.google.com/codelabs/cel-go?hl=ja#5
			https://github.com/kubernetes/api/blob/release-1.32/core/v1/generated.proto#L2997
			https://github.com/kubernetes/api/blob/release-1.32/storage/v1/generated.proto#L392
			cel.Types(
				&corev1.PersistentVolumeClaim{},
				&storagev1.StorageClass{},
			),
		*/

		// native types
		// https://qiita.com/fits/items/def30e3f6fedbd7289f9
		ext.NativeTypes(
			reflect.TypeOf(&corev1.PersistentVolumeClaim{}),
			reflect.TypeOf(&storagev1.StorageClass{}),
			reflect.TypeOf(&VolumeStats{}),
			reflect.TypeOf(&resource.Quantity{}),
			ext.ParseStructTag("json"),
		),
		// The argument of ObjectType should be equal to reflect.TypeOf(...).String()
		// ObjectType の引数は reflect.TypeOf(...).String() と同じらしい
		cel.Variable("pvc", cel.ObjectType("v1.PersistentVolumeClaim")),
		cel.Variable("sc", cel.ObjectType("v1.StorageClass")),
		cel.Variable("stats", cel.ObjectType("main.VolumeStats")),

		// helper functions
		cel.Function("deny",
			cel.Overload("deny_string", []*cel.Type{cel.StringType}, cel.IntType, cel.UnaryBinding(deny))),
		cel.Function("k8sQuantityAsInteger",
			cel.Overload("k8sQuantityAsInteger_resource.Quantity",
				[]*cel.Type{cel.ObjectType("resource.Quantity")}, cel.IntType, cel.UnaryBinding(k8sQuantityAsInteger))),
	)
	if err != nil {
		log.Fatal("NewEnv:", err)
	}

	ast, iss := env.Compile(expression)
	// raise error if the syntax check fails
	// https://github.com/google/cel-go/blob/master/examples/README.md#examples
	if err := iss.Err(); err != nil {
		log.Fatal("Compile:", err)
	}
	if ast.OutputType() != cel.IntType {
		log.Fatal("expression must return int value")
	}

	prg, err := env.Program(ast,
		// set cost limit
		cel.CostLimit(1000),
		// enable cost tracking
		cel.CostTracking(&library.CostEstimator{}),
	)
	if err != nil {
		log.Fatal("Program:", err)
	}

	// read StorageClass & PersistentVolumeClaim
	var scs storagev1.StorageClassList
	if err := yaml.Unmarshal(scsYaml, &scs); err != nil {
		log.Fatal("Unmarshal scs:", err)
	}
	scsMap := make(map[string]*storagev1.StorageClass)
	for _, i := range scs.Items {
		scsMap[i.Name] = &i
	}
	var pvcs corev1.PersistentVolumeClaimList
	if err := yaml.Unmarshal(pvcsYaml, &pvcs); err != nil {
		log.Fatal("Unmarshal pvcs:", err)
	}

	// read metrics
	var stats map[string]*VolumeStats
	if err := json.Unmarshal(metricsJson, &stats); err != nil {
		log.Fatal("Unmarshal metrics:", err)
	}

	for _, pvc := range pvcs.Items {
		// skip if sc or stats not found
		sc, ok := scsMap[*pvc.Spec.StorageClassName]
		if !ok {
			log.Printf("StorageClass %s not found for %s", *pvc.Spec.StorageClassName, pvc.Name)
			continue
		}
		stat, ok := stats[pvc.Name]
		if !ok {
			log.Printf("VolumeStats not found for %s", pvc.Name)
			continue
		}

		// evaluate!
		out, detail, err := prg.Eval(map[string]interface{}{
			"pvc":   &pvc,
			"sc":    sc,
			"stats": stat,
		})
		if err != nil {
			// もっとマシな判定方法があるはず
			if strings.HasPrefix(err.Error(), denyPrefix) {
				log.Printf("%s: %s", pvc.Name, strings.TrimPrefix(err.Error(), denyPrefix))
			} else {
				log.Printf("Error evaluating %s: %v", pvc.Name, err)
			}
			continue
		}

		// print result
		if out.Type() == cel.IntType {
			value, ok := out.Value().(int64)
			if !ok {
				log.Fatal("Type conversion failed")
			}
			log.Printf("%s res=%d, cost=%d", pvc.Name, value, *detail.ActualCost())
		} else {
			log.Printf("Unexpected type %s for %s", out.Type(), pvc.Name)
		}
	}
}

func k8sQuantityAsInteger(arg ref.Val) ref.Val {
	q, ok := arg.Value().(resource.Quantity)
	if !ok {
		return types.NewErr("helperQuantityAsInt requires resource.Quantity as an argument")
	}
	return types.Int(q.Value())
}

func deny(arg ref.Val) ref.Val {
	m, ok := arg.(types.String)
	if !ok {
		return types.NewErr("deny requires string as an argument")
	}
	return types.NewErr("%s%s", denyPrefix, string(m))
}
