package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type testConfig struct {
	Workspace string
	Args      []string
}

func readTestConfig(dir string) (testConfig, error) {
	path := filepath.Join(dir, ".tofu-test.json")
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

	var fields struct {
		Workspace json.RawMessage `json:"workspace"`
		Args      json.RawMessage `json:"args"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return testConfig{}, fmt.Errorf("%s: configuration must be a JSON object", path)
	}
	if err := decoder.Decode(&fields); err != nil {
		return testConfig{}, fmt.Errorf("%s: invalid configuration: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return testConfig{}, fmt.Errorf("%s: unexpected data after configuration", path)
	}

	var config testConfig
	if fields.Workspace != nil {
		if bytes.Equal(bytes.TrimSpace(fields.Workspace), []byte("null")) || json.Unmarshal(fields.Workspace, &config.Workspace) != nil ||
			strings.TrimSpace(config.Workspace) == "" || strings.TrimSpace(config.Workspace) != config.Workspace {
			return testConfig{}, fmt.Errorf("%s: workspace must be a non-empty string without surrounding whitespace", path)
		}
	}
	if fields.Args != nil {
		var args []json.RawMessage
		if bytes.Equal(bytes.TrimSpace(fields.Args), []byte("null")) || json.Unmarshal(fields.Args, &args) != nil {
			return testConfig{}, fmt.Errorf("%s: args must be an array of non-empty strings", path)
		}
		for _, raw := range args {
			var arg string
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &arg) != nil || arg == "" {
				return testConfig{}, fmt.Errorf("%s: args must be an array of non-empty strings", path)
			}
			config.Args = append(config.Args, arg)
		}
	}
	return config, nil
}
