package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func findTestDirs(rootDir string, extraArgs []string) ([]string, error) {
	if _, err := testDirectory(extraArgs); err != nil {
		return nil, err
	}
	rootDir = filepath.Clean(rootDir)
	testDirs := make(map[string]bool)
	modules := map[string]bool{rootDir: true}
	explicitModules := make(map[string]bool)
	configured := make(map[string]bool)
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if path != rootDir && strings.HasPrefix(info.Name(), ".") {
				if info.Name() == ".tofu-test.yaml" {
					configured[filepath.Dir(path)] = true
					modules[filepath.Dir(path)] = true
					explicitModules[filepath.Dir(path)] = true
				}
				return filepath.SkipDir
			}
			return nil
		}
		dir, name := filepath.Dir(path), info.Name()
		switch {
		case name == ".tofu-test.yaml":
			configured[dir], modules[dir], explicitModules[dir] = true, true, true
		case strings.HasSuffix(name, ".tf"), strings.HasSuffix(name, ".tofu"),
			strings.HasSuffix(name, ".tf.json"), strings.HasSuffix(name, ".tofu.json"):
			modules[dir], explicitModules[dir] = true, true
		case strings.HasSuffix(name, ".tftest.hcl"):
			testDirs[dir] = true
			if filepath.Base(dir) == "tests" && dir != rootDir {
				modules[filepath.Dir(dir)] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	selected := make(map[string][]string)
	known := make(map[string]bool)
	badConfig := make(map[string]bool)
	result := make(map[string]bool)
	for module := range modules {
		var config testConfig
		if configured[module] {
			config, err = readTestConfig(module)
			if err != nil {
				badConfig[module], result[module] = true, true
				continue
			}
		}
		configDir, err := testDirectory(config.Args)
		if err != nil {
			badConfig[module], result[module] = true, true
			continue
		}
		effectiveDir, err := testDirectory(append(slices.Clone(config.Args), extraArgs...))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", module, err)
		}
		known[resolveTestDirectory(module, "tests")] = true
		known[resolveTestDirectory(module, configDir)] = true
		target := resolveTestDirectory(module, effectiveDir)
		selected[target] = append(selected[target], module)
	}
	for dir := range testDirs {
		if explicitModules[dir] {
			result[dir] = true
		} else if withinBadConfig(dir, badConfig) {
			continue
		} else if owners, ok := selected[dir]; ok {
			for _, module := range owners {
				result[module] = true
			}
		} else if !known[dir] {
			result[dir] = true
		}
	}
	dirs := make([]string, 0, len(result))
	for dir := range result {
		dirs = append(dirs, dir)
	}
	slices.Sort(dirs)
	return dirs, nil
}

func testDirectory(args []string) (string, error) {
	dir := "tests"
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch name {
		case "--":
			return dir, nil
		case "-test-directory", "--test-directory":
			if !hasValue {
				i++
				if i >= len(args) || strings.HasPrefix(args[i], "-") {
					return "", fmt.Errorf("%s requires a directory", name)
				}
				value = args[i]
			}
			if value == "" {
				return "", fmt.Errorf("%s requires a directory", name)
			}
			dir = value
		case "-var", "--var", "-var-file", "--var-file", "-filter", "--filter",
			"-json-into", "--json-into", "-deprecation", "--deprecation":
			if !hasValue && i+1 < len(args) {
				i++
			}
		}
	}
	return dir, nil
}

func resolveTestDirectory(module, dir string) string {
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	return filepath.Join(module, dir)
}

func withinBadConfig(dir string, badConfig map[string]bool) bool {
	for parent := dir; ; parent = filepath.Dir(parent) {
		if badConfig[parent] {
			return true
		}
		if parent == filepath.Dir(parent) {
			return false
		}
	}
}
