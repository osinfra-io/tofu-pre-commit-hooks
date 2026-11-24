package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/typeexpr"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// Violation represents a single policy violation.
type Violation struct {
	File         string `json:"file"`
	Line         int    `json:"line"`
	Resource     string `json:"resource"`
	RuleID       string `json:"rule_id"`
	CISControl   string `json:"cis_control"`
	ProfileLevel string `json:"profile_level"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
}

type symbolTable struct {
	locals         map[string]interface{}
	variables      map[string]interface{}
	localValues    cty.Value
	variableValues cty.Value
}

// RunResult holds the output of a policy evaluation run.
type RunResult struct {
	Violations    []Violation
	ResourceTypes map[string]struct{}
}

// Run parses the given .tofu files and evaluates all embedded CIS policies.
func Run(ctx context.Context, files []string, policiesFS fs.FS) (*RunResult, error) {
	configs, err := parser.ParseConfigurationsAs(files, "hcl2")
	if err != nil {
		return nil, fmt.Errorf("parse tofu files: %w", err)
	}

	// Build one symbol table per module directory so that variable and local
	// definitions in any file (e.g. variables.tofu, locals.tofu) are visible
	// when resolving references in resource files (e.g. main.tofu).
	dirSymbols := buildDirSymbolTables(files)
	filesByDir := groupFilesByDir(files)
	moduleBlocksByFile := make(map[string][]*hclsyntax.Block, len(files))
	for _, file := range files {
		blocks, err := readModuleBlocks(file)
		if err != nil {
			return nil, fmt.Errorf("read module calls in %s: %w", file, err)
		}
		moduleBlocksByFile[file] = blocks
	}

	// Global existence checks need each local child module evaluated in its
	// caller's context. Resource-specific checks retain the normal per-file
	// evaluation, and global checks continue to use one merged input.
	moduleDirs := referencedLocalModuleDirs(files, filesByDir, moduleBlocksByFile, dirSymbols)

	normalizedConfigs := make(map[string]interface{}, len(configs))
	moduleConfigs := make(map[string]interface{})
	for file, config := range configs {
		dir := filepath.Clean(filepath.Dir(file))
		symbols := dirSymbols[dir]
		normalizedConfigs[file] = normalizeConfigWithSymbols(config, symbols)

		if _, isModuleDirectory := moduleDirs[dir]; isModuleDirectory {
			continue
		}

		stack := map[string]struct{}{filepath.Clean(filepath.Dir(file)): {}}
		if err := collectModuleInstanceConfigs(
			file,
			filepath.ToSlash(filepath.Clean(file)),
			symbols,
			stack,
			filesByDir,
			moduleBlocksByFile,
			configs,
			moduleConfigs,
		); err != nil {
			return nil, fmt.Errorf("resolve local modules from %s: %w", file, err)
		}
	}

	compiler, err := loadCompiler(policiesFS)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	prepared, err := rego.New(
		rego.Query("data.tofuscan.deny"),
		rego.Compiler(compiler),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare policy query: %w", err)
	}

	var violations []Violation

	// Per-file evaluation for resource-specific checks.
	for file, config := range normalizedConfigs {
		fileViolations, err := evaluate(ctx, file, config, prepared)
		if err != nil {
			return nil, fmt.Errorf("evaluate %s: %w", file, err)
		}
		for _, v := range fileViolations {
			if v.Resource != "global" {
				violations = append(violations, v)
			}
		}
	}

	// Merged evaluation for global/existence checks (e.g. "a log sink must
	// exist somewhere"). Combining all files into one input prevents
	// existence rules from firing once per file.
	//
	// Known limitation: all scanned files are merged into a single input
	// regardless of which module or project they belong to. A satisfying
	// resource in one module (e.g. a log sink) therefore suppresses a global
	// violation for every other module in the same run. Scan one project
	// directory at a time if per-project isolation is required.
	globalConfigs := make(map[string]interface{}, len(normalizedConfigs)+len(moduleConfigs))
	for file, config := range normalizedConfigs {
		if _, isModuleDirectory := moduleDirs[filepath.Clean(filepath.Dir(file))]; !isModuleDirectory {
			globalConfigs[file] = config
		}
	}
	for file, config := range moduleConfigs {
		globalConfigs[file] = config
	}
	merged := mergeConfigs(globalConfigs)
	globalViolations, err := evaluate(ctx, "", merged, prepared)
	if err != nil {
		return nil, fmt.Errorf("evaluate merged config: %w", err)
	}
	for _, v := range globalViolations {
		if v.Resource == "global" {
			violations = append(violations, v)
		}
	}

	return &RunResult{
		Violations:    violations,
		ResourceTypes: extractResourceTypes(normalizedConfigs),
	}, nil
}

type moduleInvocation struct {
	each       *resourceEachInstance
	key        string
	unresolved bool
}

func groupFilesByDir(files []string) map[string][]string {
	filesByDir := make(map[string][]string)
	for _, file := range files {
		dir := filepath.Clean(filepath.Dir(file))
		filesByDir[dir] = append(filesByDir[dir], file)
	}
	for dir := range filesByDir {
		sort.Strings(filesByDir[dir])
	}
	return filesByDir
}

func readModuleBlocks(file string) ([]*hclsyntax.Block, error) {
	source, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	parsed, diags := hclsyntax.ParseConfig(source, file, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse HCL: %s", diags.Error())
	}
	body, ok := parsed.Body.(*hclsyntax.Body)
	if !ok {
		return nil, nil
	}

	var blocks []*hclsyntax.Block
	for _, block := range body.Blocks {
		if block.Type == "module" && len(block.Labels) == 1 {
			blocks = append(blocks, block)
		}
	}
	return blocks, nil
}

func referencedLocalModuleDirs(
	files []string,
	filesByDir map[string][]string,
	moduleBlocksByFile map[string][]*hclsyntax.Block,
	dirSymbols map[string]*symbolTable,
) map[string]struct{} {
	directories := make(map[string]struct{})
	for _, file := range files {
		symbols := dirSymbols[filepath.Clean(filepath.Dir(file))]
		if symbols == nil {
			continue
		}
		for _, block := range moduleBlocksByFile[file] {
			dir, ok := localModuleDirectory(file, block, symbols)
			if ok && len(filesByDir[dir]) > 0 {
				directories[dir] = struct{}{}
			}
		}
	}
	return directories
}

func localModuleDirectory(file string, block *hclsyntax.Block, symbols *symbolTable) (string, bool) {
	sourceAttr, ok := block.Body.Attributes["source"]
	if !ok {
		return "", false
	}
	sourceValue, ok := evaluateHCLExpression(sourceAttr.Expr, symbols, nil)
	if !ok || sourceValue.Type() != cty.String {
		return "", false
	}
	source := sourceValue.AsString()
	if !filepath.IsAbs(source) && !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
		return "", false
	}
	if strings.Contains(source, "://") || strings.HasPrefix(source, "git::") {
		return "", false
	}
	if path, subdirectory, hasSubdirectory := strings.Cut(source, "//"); hasSubdirectory {
		source = filepath.Join(path, subdirectory)
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), source)), true
}

func evaluateHCLExpression(
	expression hclsyntax.Expression,
	symbols *symbolTable,
	each *resourceEachInstance,
) (cty.Value, bool) {
	if symbols == nil {
		return cty.NilVal, false
	}

	variables := map[string]cty.Value{
		"local": symbols.localValues,
		"var":   symbols.variableValues,
	}
	if each != nil {
		variables["each"] = cty.ObjectVal(map[string]cty.Value{
			"key":   each.key,
			"value": each.value,
		})
	}
	value, diags := expression.Value(&hcl.EvalContext{
		Functions: hclFunctions(),
		Variables: variables,
	})
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() {
		return cty.NilVal, false
	}
	return value, true
}

func moduleInvocations(block *hclsyntax.Block, symbols *symbolTable) []moduleInvocation {
	if countAttr, hasCount := block.Body.Attributes["count"]; hasCount {
		countValue, ok := evaluateHCLExpression(countAttr.Expr, symbols, nil)
		if !ok || countValue.Type() != cty.Number {
			return []moduleInvocation{{unresolved: true}}
		}
		count, accuracy := countValue.AsBigFloat().Int64()
		if accuracy != big.Exact || count < 0 {
			return []moduleInvocation{{unresolved: true}}
		}
		if count == 0 {
			return nil
		}
		return []moduleInvocation{{}}
	}

	forEachAttr, hasForEach := block.Body.Attributes["for_each"]
	if !hasForEach {
		return []moduleInvocation{{}}
	}

	forEachValue, ok := evaluateHCLExpression(forEachAttr.Expr, symbols, nil)
	if !ok {
		return []moduleInvocation{{unresolved: true}}
	}
	goValue, err := ctyToGo(forEachValue)
	if err != nil {
		return []moduleInvocation{{unresolved: true}}
	}
	instances, ok := resourceForEachInstances(goValue)
	if !ok {
		return []moduleInvocation{{unresolved: true}}
	}

	invocations := make([]moduleInvocation, 0, len(instances))
	for _, instance := range instances {
		keyValue, err := ctyToGo(instance.key)
		if err != nil {
			return []moduleInvocation{{unresolved: true}}
		}
		invocations = append(invocations, moduleInvocation{
			each: &instance,
			key:  fmt.Sprint(keyValue),
		})
	}
	return invocations
}

func moduleInputOverrides(
	block *hclsyntax.Block,
	symbols *symbolTable,
	each *resourceEachInstance,
) map[string]cty.Value {
	overrides := make(map[string]cty.Value)
	for name, attribute := range block.Body.Attributes {
		switch name {
		case "source", "for_each", "count", "providers", "depends_on", "version":
			continue
		}
		value, ok := evaluateHCLExpression(attribute.Expr, symbols, each)
		if !ok {
			value = unresolvedModuleInput(name)
		}
		overrides[name] = value
	}
	return overrides
}

func unresolvedModuleInput(name string) cty.Value {
	return cty.StringVal("${module_input_unresolved." + name + "}")
}

func collectModuleInstanceConfigs(
	parentFile string,
	parentNamespace string,
	parentSymbols *symbolTable,
	stack map[string]struct{},
	filesByDir map[string][]string,
	moduleBlocksByFile map[string][]*hclsyntax.Block,
	configs map[string]interface{},
	moduleConfigs map[string]interface{},
) error {
	if parentSymbols == nil {
		return nil
	}
	for _, block := range moduleBlocksByFile[parentFile] {
		childDir, ok := localModuleDirectory(parentFile, block, parentSymbols)
		if !ok || len(filesByDir[childDir]) == 0 {
			continue
		}
		if _, cyclic := stack[childDir]; cyclic {
			continue
		}

		invocations := moduleInvocations(block, parentSymbols)
		for invocationIndex, invocation := range invocations {
			overrides := moduleInputOverrides(block, parentSymbols, invocation.each)
			childSymbols, err := loadSymbolTableFromFilesWithOverrides(
				filesByDir[childDir],
				overrides,
			)
			if err != nil {
				return fmt.Errorf("load inputs for module %q: %w", block.Labels[0], err)
			}

			namespace := parentNamespace + "." + block.Labels[0]
			if invocation.key != "" {
				namespace += "[" + invocation.key + "]"
			} else if invocation.unresolved {
				namespace += "[unresolved]"
			}
			stack[childDir] = struct{}{}
			for _, childFile := range filesByDir[childDir] {
				childConfig, exists := configs[childFile]
				if !exists {
					continue
				}
				instanceConfig := normalizeConfigWithSymbols(childConfig, childSymbols)
				instanceConfig = namespaceModuleResources(instanceConfig, namespace)
				instanceKey := fmt.Sprintf("%s#module#%s#%d#%s", parentFile, namespace, invocationIndex, childFile)
				moduleConfigs[instanceKey] = instanceConfig

				if err := collectModuleInstanceConfigs(
					childFile,
					namespace,
					childSymbols,
					stack,
					filesByDir,
					moduleBlocksByFile,
					configs,
					moduleConfigs,
				); err != nil {
					return err
				}
			}
			delete(stack, childDir)
		}
	}
	return nil
}

func namespaceModuleResources(config interface{}, namespace string) interface{} {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return config
	}
	resources, ok := configMap["resource"].(map[string]interface{})
	if !ok {
		return config
	}

	namespaced := make(map[string]interface{}, len(resources))
	for resourceType, labelsValue := range resources {
		labels, ok := labelsValue.(map[string]interface{})
		if !ok {
			namespaced[resourceType] = labelsValue
			continue
		}
		namespacedLabels := make(map[string]interface{}, len(labels))
		for label, entries := range labels {
			namespacedLabels[namespace+"::"+label] = entries
		}
		namespaced[resourceType] = namespacedLabels
	}

	result := make(map[string]interface{}, len(configMap))
	for key, value := range configMap {
		if key == "resource" {
			result[key] = namespaced
		} else {
			result[key] = value
		}
	}
	return result
}

// extractResourceTypes collects the set of OpenTofu resource type names
// present across all parsed configs (e.g. "google_compute_instance").
func extractResourceTypes(configs map[string]interface{}) map[string]struct{} {
	types := make(map[string]struct{})
	for _, config := range configs {
		configMap, ok := config.(map[string]interface{})
		if !ok {
			continue
		}
		resources, ok := configMap["resource"].(map[string]interface{})
		if !ok {
			continue
		}
		for resourceType := range resources {
			types[resourceType] = struct{}{}
		}
	}
	return types
}

// loadCompiler reads all .rego files from the embedded FS and compiles them.
func loadCompiler(policiesFS fs.FS) (*ast.Compiler, error) {
	modules := make(map[string]string)

	err := fs.WalkDir(policiesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		content, err := fs.ReadFile(policiesFS, path)
		if err != nil {
			return err
		}
		modules[path] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compile rego modules: %w", err)
	}
	return compiler, nil
}

// evaluate runs all policies against a single file's parsed config.
func evaluate(ctx context.Context, file string, input interface{}, prepared rego.PreparedEvalQuery) ([]Violation, error) {
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	var violations []Violation
	lineIndex := resourceLineIndex(file)
	for _, result := range rs {
		for _, expr := range result.Expressions {
			items, ok := expr.Value.([]interface{})
			if !ok {
				continue
			}
			for _, item := range items {
				v, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				name := stringVal(v, "resource")
				violations = append(violations, Violation{
					File:         file,
					Line:         lineIndex[name],
					Resource:     name,
					RuleID:       stringVal(v, "rule_id"),
					CISControl:   stringVal(v, "cis_control"),
					ProfileLevel: stringVal(v, "profile_level"),
					Severity:     stringVal(v, "severity"),
					Title:        stringVal(v, "title"),
					Description:  stringVal(v, "description"),
				})
			}
		}
	}
	return violations, nil
}

// resourceLineIndex scans a file for HCL resource declarations and returns a
// map of "type.name" address to line number. This is a best-effort text scan —
// it does not use an HCL parser, so line numbers may be missing for resources
// with unusual formatting.
func resourceLineIndex(file string) map[string]int {
	index := make(map[string]int)
	f, err := os.Open(file)
	if err != nil {
		return index
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "resource ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			rtype := strings.Trim(parts[1], `"`)
			rname := strings.Trim(parts[2], `"{}`)
			address := rtype + "." + rname
			if _, exists := index[address]; !exists {
				index[address] = lineNum
			}
		}
	}
	// Scan errors are ignored; partial results are still useful.
	return index
}

// mergeConfigs deep-merges all per-file parsed configs into a single input.
// This lets existence/global policies (resource == "global") check whether a
// resource type is defined anywhere across the entire scan, not just per file.
func mergeConfigs(configs map[string]interface{}) interface{} {
	merged := make(map[string]interface{})
	for _, config := range configs {
		configMap, ok := config.(map[string]interface{})
		if !ok {
			continue
		}
		deepMerge(merged, configMap)
	}
	return merged
}

func deepMerge(dst, src map[string]interface{}) {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}
		dstMap, dstOk := dstVal.(map[string]interface{})
		srcMap, srcOk := srcVal.(map[string]interface{})
		if dstOk && srcOk {
			deepMerge(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
}

func stringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func normalizeConfig(file string, config interface{}, dirSymbols map[string]*symbolTable) interface{} {
	if file == "" {
		return config
	}

	dir := filepath.Clean(filepath.Dir(file))
	symbols, ok := dirSymbols[dir]
	if !ok {
		return config
	}

	return normalizeConfigWithSymbols(config, symbols)
}

func normalizeConfigWithSymbols(config interface{}, symbols *symbolTable) interface{} {
	if symbols == nil {
		return config
	}

	resolved := resolveReferences(config, symbols)
	expanded := expandDynamicBlocks(expandResourceForEach(resolved, symbols))
	return unwrapSetValues(expanded)
}

type resourceEachInstance struct {
	key   cty.Value
	value cty.Value
}

type setValues struct {
	values      []interface{}
	elementType cty.Type
}

func unwrapSetValues(value interface{}) interface{} {
	switch typed := value.(type) {
	case setValues:
		return unwrapSetValues(typed.values)
	case []interface{}:
		resolved := make([]interface{}, len(typed))
		for i, item := range typed {
			resolved[i] = unwrapSetValues(item)
		}
		return resolved
	case map[string]interface{}:
		resolved := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			resolved[key] = unwrapSetValues(item)
		}
		return resolved
	default:
		return value
	}
}

// expandResourceForEach materialises resource-level for_each blocks when their
// collections have been resolved to a concrete map or list. Unresolved blocks
// are kept unchanged so policies cannot mistake them for known configuration.
func expandResourceForEach(value interface{}, symbols *symbolTable) interface{} {
	config, ok := value.(map[string]interface{})
	if !ok {
		return value
	}
	resources, ok := config["resource"].(map[string]interface{})
	if !ok {
		return value
	}

	expandedResources := make(map[string]interface{}, len(resources))
	for resourceType, resourceLabelsValue := range resources {
		resourceLabels, ok := resourceLabelsValue.(map[string]interface{})
		if !ok {
			expandedResources[resourceType] = resourceLabelsValue
			continue
		}

		expandedLabels := make(map[string]interface{}, len(resourceLabels))
		for label, entriesValue := range resourceLabels {
			entries, ok := entriesValue.([]interface{})
			if !ok {
				expandedLabels[label] = entriesValue
				continue
			}

			expandedEntries := make([]interface{}, 0, len(entries))
			for _, entryValue := range entries {
				entry, ok := entryValue.(map[string]interface{})
				if !ok {
					expandedEntries = append(expandedEntries, entryValue)
					continue
				}
				forEach, hasForEach := entry["for_each"]
				if hasForEach {
					forEach = resolveStaticExpression(forEach, symbols)
				}
				instances, resolvable := resourceForEachInstances(forEach)
				if !hasForEach || !resolvable {
					expandedEntries = append(expandedEntries, entryValue)
					continue
				}

				for _, instance := range instances {
					materialized := make(map[string]interface{}, len(entry)-1)
					for key, attr := range entry {
						if key != "for_each" {
							materialized[key] = attr
						}
					}
					expandedEntries = append(expandedEntries, applyResourceEachValue(materialized, instance, symbols))
				}
			}
			expandedLabels[label] = expandedEntries
		}
		expandedResources[resourceType] = expandedLabels
	}

	normalized := make(map[string]interface{}, len(config))
	for key, item := range config {
		if key == "resource" {
			normalized[key] = expandedResources
		} else {
			normalized[key] = item
		}
	}
	return normalized
}

func resolveStaticExpression(value interface{}, symbols *symbolTable) interface{} {
	expressionText, ok := value.(string)
	if !ok || !strings.HasPrefix(expressionText, "${") || !strings.HasSuffix(expressionText, "}") {
		return value
	}
	expressionText = strings.TrimSuffix(strings.TrimPrefix(expressionText, "${"), "}")
	expression, diags := hclsyntax.ParseExpression(
		[]byte(expressionText),
		"<tofuscan>",
		hcl.Pos{Line: 1, Column: 1},
	)
	if diags.HasErrors() {
		return value
	}
	resolved, ok := evaluateHCLExpression(expression, symbols, nil)
	if !ok {
		return value
	}
	goValue, err := ctyToGo(resolved)
	if err != nil {
		return value
	}
	return goValue
}

func resourceForEachInstances(value interface{}) ([]resourceEachInstance, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if hasUnresolvedExpression(key) || hasUnresolvedExpression(typed[key]) {
				return nil, false
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)

		instances := make([]resourceEachInstance, 0, len(keys))
		for _, key := range keys {
			item, ok := ctyValueFromGo(typed[key])
			if !ok {
				return nil, false
			}
			instances = append(instances, resourceEachInstance{
				key:   cty.StringVal(key),
				value: item,
			})
		}
		return instances, true

	case setValues:
		return resourceForEachInstances(typed.values)

	case []interface{}:
		values := make(map[string]struct{}, len(typed))
		for _, item := range typed {
			stringValue, ok := item.(string)
			if !ok || hasUnresolvedExpression(stringValue) {
				return nil, false
			}
			values[stringValue] = struct{}{}
		}

		keys := make([]string, 0, len(values))
		for value := range values {
			keys = append(keys, value)
		}
		sort.Strings(keys)

		instances := make([]resourceEachInstance, 0, len(keys))
		for _, value := range keys {
			item := cty.StringVal(value)
			instances = append(instances, resourceEachInstance{key: item, value: item})
		}
		return instances, true

	default:
		return nil, false
	}
}

func hasUnresolvedExpression(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return strings.Contains(typed, "${")
	case []interface{}:
		for _, item := range typed {
			if hasUnresolvedExpression(item) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range typed {
			if hasUnresolvedExpression(key) || hasUnresolvedExpression(item) {
				return true
			}
		}
	case setValues:
		for _, item := range typed.values {
			if hasUnresolvedExpression(item) {
				return true
			}
		}
	}
	return false
}

func ctyValueFromGo(value interface{}) (cty.Value, bool) {
	switch typed := value.(type) {
	case setValues:
		elements := make([]cty.Value, 0, len(typed.values))
		for _, item := range typed.values {
			converted, ok := ctyValueFromGo(item)
			if !ok {
				return cty.NilVal, false
			}
			if typed.elementType != cty.NilType && typed.elementType != cty.DynamicPseudoType {
				constrained, err := convert.Convert(converted, typed.elementType)
				if err != nil {
					return cty.NilVal, false
				}
				converted = constrained
			}
			elements = append(elements, converted)
		}
		if len(elements) == 0 {
			elementType := typed.elementType
			if elementType == cty.NilType || elementType == cty.DynamicPseudoType {
				elementType = cty.String
			}
			return cty.SetValEmpty(elementType), true
		}
		return cty.SetVal(elements), true
	case map[string]interface{}:
		if len(typed) == 0 {
			return cty.EmptyObjectVal, true
		}
		attributes := make(map[string]cty.Value, len(typed))
		for name, item := range typed {
			converted, ok := ctyValueFromGo(item)
			if !ok {
				return cty.NilVal, false
			}
			attributes[name] = converted
		}
		return cty.ObjectVal(attributes), true
	case []interface{}:
		elements := make([]cty.Value, 0, len(typed))
		for _, item := range typed {
			converted, ok := ctyValueFromGo(item)
			if !ok {
				return cty.NilVal, false
			}
			elements = append(elements, converted)
		}
		return cty.TupleVal(elements), true
	case string:
		return cty.StringVal(typed), true
	case bool:
		return cty.BoolVal(typed), true
	case int:
		return cty.NumberIntVal(int64(typed)), true
	case int64:
		return cty.NumberIntVal(typed), true
	case float64:
		return cty.NumberFloatVal(typed), true
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return cty.NilVal, false
		}
		valueType, err := ctyjson.ImpliedType(encoded)
		if err != nil {
			return cty.NilVal, false
		}
		converted, err := ctyjson.Unmarshal(encoded, valueType)
		if err != nil {
			return cty.NilVal, false
		}
		return converted, true
	}
}

func applyResourceEachValue(value interface{}, instance resourceEachInstance, symbols *symbolTable) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		resolved := make([]interface{}, len(typed))
		for i, item := range typed {
			resolved[i] = applyResourceEachValue(item, instance, symbols)
		}
		return resolved
	case map[string]interface{}:
		resolved := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			if key == "dynamic" {
				resolved[key] = applyResourceEachDynamicBlocks(item, instance, symbols)
			} else {
				resolved[key] = applyResourceEachValue(item, instance, symbols)
			}
		}
		return resolved
	case string:
		if !strings.Contains(typed, "${") {
			return typed
		}

		ctx := &hcl.EvalContext{
			Functions: hclFunctions(),
			Variables: map[string]cty.Value{
				"each": cty.ObjectVal(map[string]cty.Value{
					"key":   instance.key,
					"value": instance.value,
				}),
				"local": symbols.localValues,
				"var":   symbols.variableValues,
			},
		}

		if strings.HasPrefix(typed, "${") && strings.HasSuffix(typed, "}") {
			expr := strings.TrimSuffix(strings.TrimPrefix(typed, "${"), "}")
			parsed, diags := hclsyntax.ParseExpression([]byte(expr), "<tofuscan>", hcl.Pos{Line: 1, Column: 1})
			if !diags.HasErrors() {
				resolved, diags := parsed.Value(ctx)
				if !diags.HasErrors() && resolved.IsKnown() && !resolved.IsNull() {
					goValue, err := ctyToGo(resolved)
					if err == nil {
						return goValue
					}
				}
			}
		}

		template, diags := hclsyntax.ParseTemplate([]byte(typed), "<tofuscan>", hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			return typed
		}
		resolved, diags := template.Value(ctx)
		if diags.HasErrors() || !resolved.IsKnown() || resolved.IsNull() || resolved.Type() != cty.String {
			return typed
		}
		return resolved.AsString()
	default:
		return value
	}
}

func applyResourceEachDynamicBlocks(value interface{}, instance resourceEachInstance, symbols *symbolTable) interface{} {
	dynamicBlocks, ok := value.(map[string]interface{})
	if !ok {
		return applyResourceEachValue(value, instance, symbols)
	}

	resolved := make(map[string]interface{}, len(dynamicBlocks))
	for blockName, entriesValue := range dynamicBlocks {
		entries, ok := entriesValue.([]interface{})
		if !ok {
			resolved[blockName] = applyResourceEachValue(entriesValue, instance, symbols)
			continue
		}

		resolvedEntries := make([]interface{}, len(entries))
		for i, entryValue := range entries {
			entry, ok := entryValue.(map[string]interface{})
			if !ok {
				resolvedEntries[i] = applyResourceEachValue(entryValue, instance, symbols)
				continue
			}

			iterator := blockName
			if name, ok := entry["iterator"].(string); ok && name != "" {
				iterator = strings.TrimSuffix(strings.TrimPrefix(name, "${"), "}")
			}
			resolvedEntry := make(map[string]interface{}, len(entry))
			for key, item := range entry {
				if key == "iterator" {
					resolvedEntry[key] = iterator
				} else if key == "content" && iterator == "each" {
					resolvedEntry[key] = item
				} else {
					resolvedEntry[key] = applyResourceEachValue(item, instance, symbols)
				}
			}
			resolvedEntries[i] = resolvedEntry
		}
		resolved[blockName] = resolvedEntries
	}
	return resolved
}

// expandDynamicBlocks recursively expands HCL dynamic blocks where for_each
// has been resolved to a concrete list or map. For each item in for_each it
// materialises the content template by substituting "<iterName>.value.<attr>"
// references with the corresponding attribute from that item, then promotes the
// result to a top-level key at the same map level:
//
//	"dynamic": { "X": [{"for_each": [...], "content": [...]}] }
//	→  "X": [<materialised content per item>, ...]
//
// The iterator name defaults to the block label but may be overridden via the
// optional "iterator" attribute. When for_each is a map, its values are used as
// items (map keys are not accessible in content templates at this analysis
// level). Dynamic block entries whose for_each remains unresolved are preserved
// in the output rather than silently dropped.
//
// This lets Rego policies that inspect resource attributes (e.g. database_flags)
// find the expanded values rather than the raw dynamic block structure.
func expandDynamicBlocks(value interface{}) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		result := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			result = append(result, expandDynamicBlocks(item))
		}
		return result

	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))

		// First pass: copy all non-dynamic keys (recursively expanded).
		for key, item := range typed {
			if key != "dynamic" {
				result[key] = expandDynamicBlocks(item)
			}
		}

		// Second pass: expand dynamic blocks into their block-name keys,
		// collecting any that cannot be expanded back into result["dynamic"].
		if dynVal, ok := typed["dynamic"]; ok {
			dynamicMap, ok := dynVal.(map[string]interface{})
			if !ok {
				result["dynamic"] = dynVal
				return result
			}
			remaining := make(map[string]interface{})
			for blockName, blockEntries := range dynamicMap {
				entries, ok := blockEntries.([]interface{})
				if !ok {
					remaining[blockName] = blockEntries
					continue
				}
				var unexpanded []interface{}
				for _, entry := range entries {
					entryMap, ok := entry.(map[string]interface{})
					if !ok {
						unexpanded = append(unexpanded, entry)
						continue
					}
					forEachVal, hasFE := entryMap["for_each"]
					if !hasFE {
						unexpanded = append(unexpanded, entry)
						continue
					}
					if hasUnresolvedExpression(forEachVal) {
						unexpanded = append(unexpanded, entry)
						continue
					}
					instances, ok := dynamicForEachInstances(forEachVal)
					if !ok {
						unexpanded = append(unexpanded, entry)
						continue
					}

					// Respect the optional "iterator" attribute that overrides
					// the default iteration variable name (the block label).
					iterName := blockName
					if iter, ok := entryMap["iterator"].(string); ok && iter != "" {
						iterName = strings.TrimSuffix(strings.TrimPrefix(iter, "${"), "}")
					}

					contentEntries, _ := entryMap["content"].([]interface{})
					existing, _ := result[blockName].([]interface{})
					for _, instance := range instances {
						if len(contentEntries) > 0 {
							for _, ce := range contentEntries {
								materialised := applyEachValue(ce, iterName, instance.key, instance.value)
								existing = append(existing, expandDynamicBlocks(materialised))
							}
						} else {
							existing = append(existing, expandDynamicBlocks(instance.value))
						}
					}
					result[blockName] = existing
				}
				if len(unexpanded) > 0 {
					remaining[blockName] = unexpanded
				}
			}
			if len(remaining) > 0 {
				result["dynamic"] = remaining
			}
		}

		return result

	default:
		return value
	}
}

type dynamicEachInstance struct {
	key   interface{}
	value interface{}
}

func dynamicForEachInstances(value interface{}) ([]dynamicEachInstance, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		instances := make([]dynamicEachInstance, 0, len(keys))
		for _, key := range keys {
			instances = append(instances, dynamicEachInstance{key: key, value: typed[key]})
		}
		return instances, true

	case setValues:
		instances := make([]dynamicEachInstance, 0, len(typed.values))
		for _, item := range typed.values {
			if hasUnresolvedExpression(item) {
				return nil, false
			}
			instances = append(instances, dynamicEachInstance{key: item, value: item})
		}
		return instances, true

	case []interface{}:
		instances := make([]dynamicEachInstance, 0, len(typed))
		for index, item := range typed {
			if hasUnresolvedExpression(item) {
				return nil, false
			}
			instances = append(instances, dynamicEachInstance{key: index, value: item})
		}
		return instances, true

	default:
		return nil, false
	}
}

// applyEachValue recursively replaces "${<blockName>.value.<attr>}" reference
// strings in a content template with the corresponding attribute value from
// the current for_each item. This mimics OpenTofu's dynamic block iteration
// variable (<blockName>.value) at the level of static policy analysis.
func applyEachValue(value interface{}, blockName string, key, item interface{}) interface{} {
	keyReference := blockName + ".key"
	valueReference := blockName + ".value"
	valuePrefix := valueReference + "."
	switch typed := value.(type) {
	case string:
		if !strings.HasPrefix(typed, "${") || !strings.HasSuffix(typed, "}") {
			return typed
		}
		expr := strings.TrimSuffix(strings.TrimPrefix(typed, "${"), "}")
		if expr == keyReference {
			return key
		}
		if expr == valueReference {
			return item
		}
		if strings.HasPrefix(expr, valuePrefix) {
			attr := strings.TrimPrefix(expr, valuePrefix)
			if itemMap, ok := item.(map[string]interface{}); ok {
				if v, exists := lookupReference(itemMap, strings.Split(attr, ".")); exists {
					return v
				}
			}
		}
		return typed
	case map[string]interface{}:
		resolved := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			if k == "dynamic" {
				resolved[k] = applyEachValueToDynamicBlocks(v, blockName, key, item)
			} else {
				resolved[k] = applyEachValue(v, blockName, key, item)
			}
		}
		return resolved
	case []interface{}:
		resolved := make([]interface{}, len(typed))
		for i, v := range typed {
			resolved[i] = applyEachValue(v, blockName, key, item)
		}
		return resolved
	default:
		return value
	}
}

func applyEachValueToDynamicBlocks(value interface{}, blockName string, key, item interface{}) interface{} {
	dynamicBlocks, ok := value.(map[string]interface{})
	if !ok {
		return applyEachValue(value, blockName, key, item)
	}

	resolved := make(map[string]interface{}, len(dynamicBlocks))
	for nestedBlockName, entriesValue := range dynamicBlocks {
		entries, ok := entriesValue.([]interface{})
		if !ok {
			resolved[nestedBlockName] = applyEachValue(entriesValue, blockName, key, item)
			continue
		}

		resolvedEntries := make([]interface{}, len(entries))
		for index, entryValue := range entries {
			entry, ok := entryValue.(map[string]interface{})
			if !ok {
				resolvedEntries[index] = applyEachValue(entryValue, blockName, key, item)
				continue
			}

			nestedIterator := nestedBlockName
			if iterator, ok := entry["iterator"].(string); ok && iterator != "" {
				nestedIterator = strings.TrimSuffix(strings.TrimPrefix(iterator, "${"), "}")
			}
			resolvedEntry := make(map[string]interface{}, len(entry))
			for name, entryItem := range entry {
				if name == "content" && nestedIterator == blockName {
					resolvedEntry[name] = entryItem
				} else {
					resolvedEntry[name] = applyEachValue(entryItem, blockName, key, item)
				}
			}
			resolvedEntries[index] = resolvedEntry
		}
		resolved[nestedBlockName] = resolvedEntries
	}
	return resolved
}

// buildDirSymbolTables groups the given files by directory and builds one
// merged symbol table per directory so that variable defaults and locals
// defined in any file within a module are visible when resolving references
// in other files of the same module.
func buildDirSymbolTables(files []string) map[string]*symbolTable {
	byDir := make(map[string][]string)
	for _, file := range files {
		dir := filepath.Clean(filepath.Dir(file))
		byDir[dir] = append(byDir[dir], file)
	}

	dirSymbols := make(map[string]*symbolTable, len(byDir))
	for dir, dirFiles := range byDir {
		symbols, err := loadSymbolTableFromFiles(dirFiles)
		if err != nil {
			continue
		}
		dirSymbols[dir] = symbols
	}
	return dirSymbols
}

func loadSymbolTableFromFiles(files []string) (*symbolTable, error) {
	return loadSymbolTableFromFilesWithOverrides(files, nil)
}

func loadSymbolTableFromFilesWithOverrides(
	files []string,
	overrides map[string]cty.Value,
) (*symbolTable, error) {
	variables := make(map[string]cty.Value)
	variableTypes := make(map[string]cty.Type)
	pending := make(map[string]*hclsyntax.Attribute)

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		f, diags := hclsyntax.ParseConfig(src, file, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			continue
		}

		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}

		for name, value := range collectVariableDefaults(body) {
			variables[name] = value
		}

		for _, block := range body.Blocks {
			if block.Type != "variable" || len(block.Labels) != 1 {
				continue
			}
			name := block.Labels[0]
			if typeAttr, ok := block.Body.Attributes["type"]; ok {
				constraint, typeDiags := typeexpr.TypeConstraint(typeAttr.Expr)
				if !typeDiags.HasErrors() {
					variableTypes[name] = constraint
				}
			}
		}

		for _, block := range body.Blocks {
			if block.Type != "locals" {
				continue
			}
			for name, attr := range block.Body.Attributes {
				pending[name] = attr
			}
		}
	}

	for name, value := range overrides {
		if variableType, ok := variableTypes[name]; ok &&
			variableType != cty.DynamicPseudoType &&
			variableType != cty.NilType {
			converted, err := convert.Convert(value, variableType)
			if err != nil {
				value = unresolvedModuleInput(name)
			} else {
				value = converted
			}
		}
		variables[name] = value
	}

	locals := resolveLocals(pending, variables) // resolves inter-local and var references

	variableValues, err := ctyMapToGo(variables)
	if err != nil {
		return nil, err
	}
	localValues, err := ctyMapToGo(locals)
	if err != nil {
		return nil, err
	}

	return &symbolTable{
		locals:         localValues,
		variables:      variableValues,
		localValues:    ctyObject(locals),
		variableValues: ctyObject(variables),
	}, nil
}

func collectVariableDefaults(body *hclsyntax.Body) map[string]cty.Value {
	defaults := make(map[string]cty.Value)
	for _, block := range body.Blocks {
		if block.Type != "variable" || len(block.Labels) != 1 {
			continue
		}

		attr, ok := block.Body.Attributes["default"]
		if !ok {
			continue
		}

		value, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}

		if typeAttr, ok := block.Body.Attributes["type"]; ok {
			constraint, typeDiags := typeexpr.TypeConstraint(typeAttr.Expr)
			if !typeDiags.HasErrors() {
				if constrained, err := convert.Convert(value, constraint); err == nil {
					value = constrained
				}
			}
		}

		defaults[block.Labels[0]] = value
	}

	return defaults
}

func resolveLocals(pending map[string]*hclsyntax.Attribute, variables map[string]cty.Value) map[string]cty.Value {

	locals := make(map[string]cty.Value)
	for len(pending) > 0 {
		resolvedAny := false
		ctx := &hcl.EvalContext{
			Functions: hclFunctions(),
			Variables: map[string]cty.Value{
				"local": ctyObject(locals),
				"var":   ctyObject(variables),
			},
		}

		for name, attr := range pending {
			value, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() {
				continue
			}

			locals[name] = value
			delete(pending, name)
			resolvedAny = true
		}

		if !resolvedAny {
			break
		}
	}

	return locals
}

func ctyObject(values map[string]cty.Value) cty.Value {
	if len(values) == 0 {
		return cty.EmptyObjectVal
	}

	return cty.ObjectVal(values)
}

func ctyMapToGo(values map[string]cty.Value) (map[string]interface{}, error) {
	converted := make(map[string]interface{}, len(values))
	for name, value := range values {
		goValue, err := ctyToGo(value)
		if err != nil {
			return nil, err
		}
		converted[name] = goValue
	}
	return converted, nil
}

func ctyToGo(value cty.Value) (interface{}, error) {
	if !value.IsKnown() {
		return nil, fmt.Errorf("cannot convert an unknown cty value to Go")
	}
	if value.IsNull() {
		return nil, nil
	}

	switch {
	case value.Type().IsSetType():
		values := make([]interface{}, 0, value.LengthInt())
		iterator := value.ElementIterator()
		for iterator.Next() {
			_, element := iterator.Element()
			converted, err := ctyToGo(element)
			if err != nil {
				return nil, err
			}
			values = append(values, converted)
		}
		return setValues{values: values, elementType: value.Type().ElementType()}, nil
	case value.Type().IsListType(), value.Type().IsTupleType():
		values := make([]interface{}, 0, value.LengthInt())
		iterator := value.ElementIterator()
		for iterator.Next() {
			_, element := iterator.Element()
			converted, err := ctyToGo(element)
			if err != nil {
				return nil, err
			}
			values = append(values, converted)
		}
		return values, nil
	case value.Type().IsMapType(), value.Type().IsObjectType():
		values := make(map[string]interface{}, value.LengthInt())
		iterator := value.ElementIterator()
		for iterator.Next() {
			key, element := iterator.Element()
			converted, err := ctyToGo(element)
			if err != nil {
				return nil, err
			}
			values[key.AsString()] = converted
		}
		return values, nil
	}

	encoded, err := ctyjson.Marshal(value, value.Type())
	if err != nil {
		return nil, err
	}

	var out interface{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func resolveReferences(value interface{}, symbols *symbolTable) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		resolved := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			resolved = append(resolved, resolveReferences(item, symbols))
		}
		return resolved
	case map[string]interface{}:
		resolved := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			resolved[key] = resolveReferences(item, symbols)
		}
		return resolved
	case string:
		if resolved, ok := resolveReferenceString(typed, symbols); ok {
			return resolveReferences(resolved, symbols)
		}
		return typed
	default:
		return value
	}
}

func resolveReferenceString(value string, symbols *symbolTable) (interface{}, bool) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return nil, false
	}

	expr := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
	switch {
	case strings.HasPrefix(expr, "var."):
		path := strings.Split(strings.TrimPrefix(expr, "var."), ".")
		resolved, ok := lookupReference(symbols.variables, path)
		if !ok {
			return nil, false
		}
		if value, ok := lookupCtyReference(symbols.variableValues, path); ok && value.Type().IsSetType() {
			if values, ok := resolved.([]interface{}); ok {
				return setValues{values: values, elementType: value.Type().ElementType()}, true
			}
		}
		return resolved, true
	case strings.HasPrefix(expr, "local."):
		path := strings.Split(strings.TrimPrefix(expr, "local."), ".")
		resolved, ok := lookupReference(symbols.locals, path)
		if !ok {
			return nil, false
		}
		if value, ok := lookupCtyReference(symbols.localValues, path); ok && value.Type().IsSetType() {
			if values, ok := resolved.([]interface{}); ok {
				return setValues{values: values, elementType: value.Type().ElementType()}, true
			}
		}
		return resolved, true
	default:
		return nil, false
	}
}

func lookupCtyReference(root cty.Value, path []string) (cty.Value, bool) {
	current := root
	for _, segment := range path {
		if !current.IsKnown() || current.IsNull() {
			return cty.NilVal, false
		}

		switch ty := current.Type(); {
		case ty.IsObjectType():
			if !ty.HasAttribute(segment) {
				return cty.NilVal, false
			}
			current = current.GetAttr(segment)
		case ty.IsMapType():
			key := cty.StringVal(segment)
			if !current.HasIndex(key).True() {
				return cty.NilVal, false
			}
			current = current.Index(key)
		case ty.IsListType(), ty.IsTupleType():
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 {
				return cty.NilVal, false
			}
			key := cty.NumberIntVal(int64(index))
			if !current.HasIndex(key).True() {
				return cty.NilVal, false
			}
			current = current.Index(key)
		default:
			return cty.NilVal, false
		}
	}
	return current, true
}

func lookupReference(root map[string]interface{}, path []string) (interface{}, bool) {
	if len(path) == 0 {
		return nil, false
	}

	current, ok := root[path[0]]
	if !ok {
		return nil, false
	}

	for _, segment := range path[1:] {
		switch typed := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = typed[segment]
			if !ok {
				return nil, false
			}
		case []interface{}:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}

	return current, true
}
