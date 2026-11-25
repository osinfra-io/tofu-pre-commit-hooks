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

func TestFindTestDirs_CustomDirectoriesAndModulesNamedTests(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		args  []string
		want  []string
	}{
		{
			name:  "standalone tests module",
			files: map[string]string{"modules/tests/main.tf": "", "modules/tests/check.tftest.hcl": "", "modules/tests/.tofu-test.yaml": "workspace: sandbox\n"},
			want:  []string{"modules/tests"},
		},
		{
			name:  "standalone tests module without config",
			files: map[string]string{"modules/tests/main.tofu": "", "modules/tests/check.tftest.hcl": ""},
			want:  []string{"modules/tests"},
		},
		{
			name:  "shared equals flag",
			files: map[string]string{"main.tf": "", "checks/check.tftest.hcl": ""},
			args:  []string{"-test-directory=checks"},
			want:  []string{"."},
		},
		{
			name:  "shared split flag",
			files: map[string]string{"main.tf": "", "checks/check.tftest.hcl": ""},
			args:  []string{"-test-directory", "checks"},
			want:  []string{"."},
		},
		{
			name:  "per-module nested directory",
			files: map[string]string{"module/main.tf": "", "module/.tofu-test.yaml": "args: [-test-directory, checks/unit]\n", "module/checks/unit/check.tftest.hcl": ""},
			want:  []string{"module"},
		},
		{
			name:  "shared flag overrides module flag",
			files: map[string]string{"main.tf": "", ".tofu-test.yaml": "args: [-test-directory=old]\n", "old/check.tftest.hcl": "", "new/check.tftest.hcl": ""},
			args:  []string{"-test-directory", "new"},
			want:  []string{"."},
		},
		{
			name:  "unselected custom tests do not become modules",
			files: map[string]string{"main.tf": "", ".tofu-test.yaml": "args: [-test-directory=old]\n", "old/check.tftest.hcl": ""},
			args:  []string{"-test-directory=new"},
		},
		{
			name:  "unselected default tests do not become modules",
			files: map[string]string{"main.tf": "", "tests/check.tftest.hcl": ""},
			args:  []string{"-test-directory=checks"},
		},
		{
			name:  "unconfigured standalone test",
			files: map[string]string{"standalone/check.tftest.hcl": ""},
			want:  []string{"standalone"},
		},
		{
			name:  "malformed config does not run its unknown test directory",
			files: map[string]string{"module/.tofu-test.yaml": "args: [\n", "module/checks/check.tftest.hcl": "", "other/main.tf": "", "other/check.tftest.hcl": ""},
			want:  []string{"module", "other"},
		},
		{
			name:  "invalid custom flag does not run its unknown test directory",
			files: map[string]string{"module/.tofu-test.yaml": "args: [-test-directory]\n", "module/checks/check.tftest.hcl": "", "other/main.tf": "", "other/check.tftest.hcl": ""},
			want:  []string{"module", "other"},
		},
		{
			name: "invalid root config preserves independent modules",
			files: map[string]string{
				".tofu-test.yaml":                 "args: [\n",
				"module/main.tf":                  "",
				"module/tests/check.tftest.hcl":   "",
				"custom/.tofu-test.yaml":          "args: [-test-directory=checks]\n",
				"custom/checks/check.tftest.hcl":  "",
				"unknown/tests/check.tftest.hcl":  "",
				"unknown/checks/check.tftest.hcl": "",
			},
			want: []string{".", "custom", "module"},
		},
		{
			name: "invalid nested config prevents using an ancestor module",
			files: map[string]string{
				"main.tf":                        "",
				".tofu-test.yaml":                "args: [-test-directory=broken/checks]\n",
				"broken/.tofu-test.yaml":         "args: [\n",
				"broken/checks/check.tftest.hcl": "",
			},
			want: []string{"broken"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for name, content := range tt.files {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			dirs, err := findTestDirs(root, tt.args)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, dir := range dirs {
				rel, err := filepath.Rel(root, dir)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, rel)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findTestDirs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunTofuTestCLI_InvalidRootConfigRunsNestedModules(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		".tofu-test.yaml":                "args: [\n",
		"module/main.tf":                 "",
		"module/tests/check.tftest.hcl":  "",
		"custom/.tofu-test.yaml":         "workspace: sandbox\nargs: [-test-directory=checks]\n",
		"custom/checks/check.tftest.hcl": "",
		"unknown/tests/check.tftest.hcl": "",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	visited := make(map[string]string)
	var summary string
	err := RunTofuTestCLI(nil, func() bool { return true }, func() (string, error) { return root, nil },
		findTestDirs, func(dir string, _ []string, workspace string) (string, error) {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				t.Fatal(err)
			}
			visited[rel] = workspace
			return "passed", nil
		}, func(_, msg string) { summary = msg })
	if err == nil || !strings.Contains(err.Error(), ".tofu-test.yaml") {
		t.Errorf("expected root config error, got %v", err)
	}
	if want := map[string]string{"custom": "sandbox", "module": ""}; !reflect.DeepEqual(visited, want) {
		t.Errorf("visited = %v, want %v", visited, want)
	}
	if summary != "2/3 test directories passed  ·  1 failed" {
		t.Errorf("summary = %q", summary)
	}
}

func TestRunTofuTestCLI_StandaloneTestsModuleAndInvalidConfig(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"modules/tests/main.tf":          "",
		"modules/tests/check.tftest.hcl": "",
		"modules/tests/.tofu-test.yaml":  "workspace: sandbox\nargs: [-verbose]\n",
		"broken/.tofu-test.yaml":         "args: [-test-directory]\n",
		"broken/checks/check.tftest.hcl": "",
		"other/main.tf":                  "",
		"other/tests/check.tftest.hcl":   "",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	visited := make(map[string]string)
	err := RunTofuTestCLI(nil, func() bool { return true }, func() (string, error) { return root, nil },
		findTestDirs, func(dir string, args []string, workspace string) (string, error) {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				t.Fatal(err)
			}
			visited[rel] = workspace
			if rel == "modules/tests" && !reflect.DeepEqual(args, []string{"-verbose"}) {
				t.Errorf("module args = %v", args)
			}
			return "passed", nil
		}, func(string, string) {})
	if err == nil || !strings.Contains(err.Error(), "-test-directory requires a directory") {
		t.Errorf("expected invalid config error, got %v", err)
	}
	if want := map[string]string{"modules/tests": "sandbox", "other": ""}; !reflect.DeepEqual(visited, want) {
		t.Errorf("visited = %v, want %v", visited, want)
	}
}

func TestTestDirectoryFlag(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
		bad  bool
	}{
		{nil, "tests", false},
		{[]string{"-test-directory=first", "-test-directory", "second"}, "second", false},
		{[]string{"--test-directory=checks"}, "checks", false},
		{[]string{"-var", "-test-directory=not-a-flag"}, "tests", false},
		{[]string{"--", "-test-directory=ignored"}, "tests", false},
		{[]string{"-test-directory"}, "", true},
		{[]string{"-test-directory="}, "", true},
	} {
		got, err := testDirectory(tt.args)
		if got != tt.want || (err != nil) != tt.bad {
			t.Errorf("testDirectory(%v) = %q, %v; want %q, error %v", tt.args, got, err, tt.want, tt.bad)
		}
	}
}

func TestRunTofuTestCLI_RealCustomTestDirectory(t *testing.T) {
	testutil.SkipIfTofuNotInstalled(t)
	for _, tt := range []struct {
		name   string
		config string
		args   []string
	}{
		{"shared equals", "", []string{"-test-directory=checks"}},
		{"shared split", "", []string{"-test-directory", "checks"}},
		{"per-module", "args: [-test-directory=checks]\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "checks"), 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"main.tf": `output "value" { value = "correct module" }`,
				"checks/check.tftest.hcl": `
run "check" {
  command = plan
  assert {
    condition = output.value == "correct module"
    error_message = "wrong module"
  }
}
`,
			}
			if tt.config != "" {
				files[".tofu-test.yaml"] = tt.config
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("tofu", "init", "-input=false", "-backend=false", "-no-color")
			cmd.Dir = root
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("tofu init: %v\n%s", err, out)
			}
			var outputs []string
			args := append([]string{"-no-color"}, tt.args...)
			err := RunTofuTestCLI(args, func() bool { return true }, func() (string, error) { return root, nil },
				findTestDirs, func(dir string, args []string, workspace string) (string, error) {
					out, err := runTofuTest(dir, args, workspace)
					outputs = append(outputs, out)
					return out, err
				}, func(string, string) {})
			if err != nil || len(outputs) != 1 || !strings.Contains(outputs[0], "Success! 1 passed, 0 failed.") {
				t.Fatalf("run = %v, outputs %v", err, outputs)
			}
		})
	}
}
