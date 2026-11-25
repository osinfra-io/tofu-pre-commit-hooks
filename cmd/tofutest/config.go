package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type testConfig struct {
	Workspace string
	Args      []string
}

func readTestConfig(dir string) (testConfig, error) {
	path := filepath.Join(dir, ".tofu-test.yaml")
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return testConfig{}, nil
		}
		return testConfig{}, fmt.Errorf("reading %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return testConfig{}, fmt.Errorf("reading %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return testConfig{}, fmt.Errorf("%s: invalid configuration: %w", path, err)
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return testConfig{}, fmt.Errorf("%s: unexpected data after configuration", path)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return testConfig{}, fmt.Errorf("%s: configuration must be a YAML mapping", path)
	}
	var config testConfig
	seen := make(map[string]bool)
	fields := document.Content[0].Content
	for i := 0; i < len(fields); i += 2 {
		key, value := fields[i], fields[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return testConfig{}, fmt.Errorf("%s: configuration keys must be strings", path)
		}
		if seen[key.Value] {
			return testConfig{}, fmt.Errorf("%s: duplicate field %q", path, key.Value)
		}
		seen[key.Value] = true
		switch key.Value {
		case "workspace":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || strings.TrimSpace(value.Value) == "" || strings.TrimSpace(value.Value) != value.Value {
				return testConfig{}, fmt.Errorf("%s: workspace must be a non-empty string without surrounding whitespace", path)
			}
			config.Workspace = value.Value
		case "args":
			if value.Kind != yaml.SequenceNode {
				return testConfig{}, fmt.Errorf("%s: args must be a list of non-empty strings", path)
			}
			for _, arg := range value.Content {
				if arg.Kind != yaml.ScalarNode || arg.Tag != "!!str" || arg.Value == "" {
					return testConfig{}, fmt.Errorf("%s: args must be a list of non-empty strings", path)
				}
				config.Args = append(config.Args, arg.Value)
			}
		default:
			return testConfig{}, fmt.Errorf("%s: unknown field %q", path, key.Value)
		}
	}
	return config, nil
}
