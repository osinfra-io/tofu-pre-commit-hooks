package engine

import (
	"fmt"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// hclFunctions returns the minimal set of HCL/OpenTofu built-in functions
// needed to evaluate locals that use common string and collection operations.
// Only functions that appear in real-world module locals are included.
func hclFunctions() map[string]function.Function {
	return map[string]function.Function{
		"concat":     concatFn,
		"endswith":   endsWithFn,
		"merge":      stdlib.MergeFunc,
		"startswith": startsWithFn,
		"toset":      toSetFn,
	}
}

// startsWithFn implements the OpenTofu startswith(str, prefix) built-in.
var startsWithFn = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "prefix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasPrefix(args[0].AsString(), args[1].AsString())), nil
	},
})

// endsWithFn implements the OpenTofu endswith(str, suffix) built-in.
var endsWithFn = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "str", Type: cty.String},
		{Name: "suffix", Type: cty.String},
	},
	Type: function.StaticReturnType(cty.Bool),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.BoolVal(strings.HasSuffix(args[0].AsString(), args[1].AsString())), nil
	},
})

// concatFn implements the OpenTofu concat(lists...) built-in.
// It concatenates any number of lists or tuples into a single tuple value.
// Returns an error for any argument that is not a list or tuple type, matching
// OpenTofu's behaviour.
// A tuple is used as the return type to accommodate lists with differing
// element types (e.g. list(object) merged with list(object)).
var concatFn = function.New(&function.Spec{
	VarParam: &function.Parameter{
		Name:             "seqs",
		Type:             cty.DynamicPseudoType,
		AllowDynamicType: true,
	},
	Type: function.StaticReturnType(cty.DynamicPseudoType),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		var elems []cty.Value
		for i, arg := range args {
			ty := arg.Type()
			if !ty.IsListType() && !ty.IsTupleType() {
				return cty.NilVal, fmt.Errorf("argument %d: list or tuple required, got %s", i+1, ty.FriendlyName())
			}
			for it := arg.ElementIterator(); it.Next(); {
				_, v := it.Element()
				elems = append(elems, v)
			}
		}
		if len(elems) == 0 {
			return cty.TupleVal([]cty.Value{}), nil
		}
		return cty.TupleVal(elems), nil
	},
})

var toSetFn = function.New(&function.Spec{
	Params: []function.Parameter{
		{Name: "collection", Type: cty.DynamicPseudoType, AllowDynamicType: true},
	},
	Type: function.StaticReturnType(cty.DynamicPseudoType),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		collection := args[0]
		ty := collection.Type()
		if ty.IsSetType() {
			return collection, nil
		}
		if !ty.IsListType() && !ty.IsTupleType() {
			return cty.NilVal, fmt.Errorf("list, tuple, or set required, got %s", ty.FriendlyName())
		}

		var elements []cty.Value
		for iterator := collection.ElementIterator(); iterator.Next(); {
			_, element := iterator.Element()
			elements = append(elements, element)
		}
		if len(elements) == 0 {
			return cty.SetValEmpty(cty.DynamicPseudoType), nil
		}
		types := make([]cty.Type, len(elements))
		for i, element := range elements {
			types[i] = element.Type()
		}
		elementType, conversions := convert.Unify(types)
		if elementType == cty.NilType {
			return cty.NilVal, fmt.Errorf("cannot convert collection elements to one set type")
		}
		for i, conversion := range conversions {
			if conversion != nil {
				converted, err := conversion(elements[i])
				if err != nil {
					return cty.NilVal, err
				}
				elements[i] = converted
			}
		}
		return cty.SetVal(elements), nil
	},
})
