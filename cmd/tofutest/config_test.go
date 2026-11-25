package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tofu-pre-commit-hooks/internal/testutil"
)

func TestReadTestConfig(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    testConfig
		invalid bool
	}{
		{name: "empty object", content: `{}`},
		{name: "configured", content: `{"workspace":"sandbox","args":["-var-file=../teams.tfvars","-var","environment=sandbox"]}`,
			want: testConfig{Workspace: "sandbox", Args: []string{"-var-file=../teams.tfvars", "-var", "environment=sandbox"}}},
		{name: "syntax", content: `{"workspace":`, invalid: true},
		{name: "not object", content: `null`, invalid: true},
		{name: "unknown field", content: `{"workpace":"sandbox"}`, invalid: true},
		{name: "trailing data", content: `{} {}`, invalid: true},
		{name: "null workspace", content: `{"workspace":null}`, invalid: true},
		{name: "blank workspace", content: `{"workspace":" "}`, invalid: true},
		{name: "non-string workspace", content: `{"workspace":2}`, invalid: true},
		{name: "null args", content: `{"args":null}`, invalid: true},
		{name: "wrong args", content: `{"args":"-verbose"}`, invalid: true},
		{name: "null argument", content: `{"args":[null]}`, invalid: true},
		{name: "empty argument", content: `{"args":[""]}`, invalid: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".tofu-test.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := readTestConfig(dir)
			if tt.invalid {
				if err == nil || !strings.Contains(err.Error(), path) {
					t.Fatalf("expected error identifying %s, got %v", path, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("readTestConfig() = %#v, %v; want %#v", got, err, tt.want)
			}
		})
	}
}

func TestReadTestConfigMissingAndUnreadable(t *testing.T) {
	dir := t.TempDir()
	if got, err := readTestConfig(dir); err != nil || !reflect.DeepEqual(got, testConfig{}) {
		t.Fatalf("missing config = %#v, %v", got, err)
	}
	path := filepath.Join(dir, ".tofu-test.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestConfig(dir); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("expected read error identifying %s, got %v", path, err)
	}
}

func TestRunTofuTestCLI_DirectoryConfiguration(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	stub := `#!/bin/sh
printf '%s\n' "$TF_WORKSPACE" "$@" > invocation.log
case "$PWD" in *e-fail) echo "intentional failure"; exit 1;; esac
`
	if err := os.WriteFile(filepath.Join(bin, "tofu"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TF_WORKSPACE", "inherited")
	configs := map[string]string{
		"a-invalid":    `{"workspace":null}`,
		"b-configured": `{"workspace":"sandbox","args":["-var-file=../teams.tfvars","-var=env=local"]}`,
		"c-configured": `{"workspace":"regional","args":["-var-file","../regional.tfvars"]}`,
		"d-inherited":  "",
		"e-fail":       "",
	}
	var dirs []string
	for _, name := range []string{"a-invalid", "b-configured", "c-configured", "d-inherited", "e-fail"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if configs[name] != "" {
			if err := os.WriteFile(filepath.Join(dir, ".tofu-test.json"), []byte(configs[name]), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		dirs = append(dirs, dir)
	}

	err := RunTofuTestCLI(
		[]string{"-var=env=shared", "-no-color"},
		func() bool { return true },
		func() (string, error) { return root, nil },
		func(string) ([]string, error) { return dirs, nil },
		runTofuTest,
		func(string, string) {},
	)
	if err == nil || !strings.Contains(err.Error(), "a-invalid") || !strings.Contains(err.Error(), "e-fail") {
		t.Fatalf("expected config and test failures, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirs[0], "invocation.log")); !os.IsNotExist(err) {
		t.Fatalf("invalid configuration must not run tofu: %v", err)
	}
	want := map[string]string{
		"b-configured": "sandbox\ntest\n-var-file=../teams.tfvars\n-var=env=local\n-var=env=shared\n-no-color\n",
		"c-configured": "regional\ntest\n-var-file\n../regional.tfvars\n-var=env=shared\n-no-color\n",
		"d-inherited":  "inherited\ntest\n-var=env=shared\n-no-color\n",
		"e-fail":       "inherited\ntest\n-var=env=shared\n-no-color\n",
	}
	for name, expected := range want {
		got, err := os.ReadFile(filepath.Join(root, name, "invocation.log"))
		if err != nil || string(got) != expected {
			t.Errorf("%s invocation = %q, %v; want %q", name, got, err, expected)
		}
	}
	if got := os.Getenv("TF_WORKSPACE"); got != "inherited" {
		t.Errorf("parent TF_WORKSPACE changed to %q", got)
	}
}

func TestRunTofuTestCLI_RealVariableFileAndWorkspace(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	t.Setenv("TF_WORKSPACE", "")
	root := t.TempDir()
	dir := filepath.Join(root, "module")
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"teams.tfvars": `team = "platform"` + "\n",
		"module/main.tf": `
variable "team" { type = string }
variable "priority" { type = string }
output "team" { value = var.team }
output "priority" { value = var.priority }
output "workspace" { value = terraform.workspace }
`,
		"module/tests/check.tftest.hcl": `
run "check" {
  command = plan
  assert {
    condition = output.team == "platform" && output.priority == "shared" && output.workspace == "sandbox"
    error_message = "wrong inputs or workspace"
  }
}
`,
		"module/.tofu-test.json": `{"workspace":"sandbox","args":["-var-file=../teams.tfvars","-var=priority=directory"]}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-input=false", "-backend=false", "-no-color"}, {"workspace", "new", "sandbox", "-no-color"}} {
		cmd := exec.Command("tofu", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("tofu %v: %v\n%s", args, err, out)
		}
	}
	err := RunTofuTestCLI(
		[]string{"-no-color", "-var=priority=shared"},
		func() bool { return true },
		func() (string, error) { return root, nil },
		findTestDirs,
		runTofuTest,
		func(string, string) {},
	)
	if err != nil {
		t.Fatal(err)
	}
}
