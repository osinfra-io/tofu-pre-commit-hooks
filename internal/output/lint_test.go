package output

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestParseLintFindings(t *testing.T) {
	raw := `╷
│ Warning: Input variable not used (core:unused-variable)
│
│   on variables.tofu line 67:
│   67: variable "state_bucket" {
│
│ Found no usage of the variable "state_bucket".
╵
Warning: Experimental linting enabled
The linting functionality is under active development.
Warning: A warning without a rule
Additional details
on a second line.
Error: Invalid configuration
Do not include this error in the warning card.
Success! The configuration is valid, but there were some validation warnings
as shown above.`
	want := []lintFinding{
		{
			title:       "Input variable not used",
			rule:        "core:unused-variable",
			location:    "variables.tofu:67",
			description: []string{`Found no usage of the variable "state_bucket".`},
		},
		{
			title:       "A warning without a rule",
			description: []string{"Additional details", "on a second line."},
		},
	}

	if got := parseLintFindings(raw, "warning"); !reflect.DeepEqual(got, want) {
		t.Errorf("parseLintFindings() = %#v, want %#v", got, want)
	}
	wantErrors := []lintFinding{{title: "Invalid configuration", description: []string{"Do not include this error in the warning card."}}}
	if got := parseLintFindings(raw, "error"); !reflect.DeepEqual(got, wantErrors) {
		t.Errorf("parseLintFindings(errors) = %#v, want %#v", got, wantErrors)
	}
}

func TestPrintLintWarningSummary_PreservesLocations(t *testing.T) {
	raw := func(file string, line int) string {
		return fmt.Sprintf("╷\n│ Warning: Input variable not used (core:unused-variable)\n│\n│   on %s line %d:\n│   %d: variable \"project\" {\n│\n│ Found no usage of the variable \"project\".\n╵", file, line, line)
	}
	messages := []TofuMessage{
		{Step: "lint", RelPath: "repo/a", Output: raw("variables.tofu", 16)},
		{Step: "lint", RelPath: "repo/b", Output: raw("inputs.tofu", 42)},
		{Step: "lint", RelPath: "repo/c", Output: raw("variables.tofu", 16)},
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	PrintLintWarningSummary(messages)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	got := string(captured)
	for _, location := range []string{"repo/a/variables.tofu:16", "repo/b/inputs.tofu:42", "repo/c/variables.tofu:16"} {
		if !strings.Contains(got, location) {
			t.Errorf("output missing %q:\n%s", location, got)
		}
	}
	if strings.Contains(got, "repo/b/variables.tofu:16") {
		t.Errorf("output reused another directory's location:\n%s", got)
	}
	if count := strings.Count(got, Badge("WARNING", BoldYellow)); count != 2 {
		t.Errorf("got %d warning cards, want 2 with identical diagnostics grouped:\n%s", count, got)
	}
}

func TestPrintLintErrorSummary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		step    string
		raw     string
		want    []string
		exclude []string
	}{
		{
			name: "mixed diagnostics",
			step: "lint",
			raw: `Warning: Experimental linting enabled
The linting functionality is under active development.
Warning: Local value not used (core:unused-local)
  on cluster.tofu line 39:
Found no usage of the local value "instances".
Error: Reference to undeclared local value
  on cluster.tofu line 43:
  43: workspace_valid = local.stage
A local value with the name "stage" has not been declared.
Warning: Another warning
Warning details must not appear in the error card.
Error: Another error
Another error's details.`,
			want:    []string{"[ERROR]", "Reference to undeclared local value", "repo/shared/cluster.tofu:43", `A local value with the name "stage" has not been declared.`, "Another error's details."},
			exclude: []string{"Experimental linting", "active development", "instances", "39", "43:", "workspace_valid", "Warning details", "Another warning"},
		},
		{
			name: "unstructured runtime failure",
			step: "lint",
			raw:  "Failed to load plugin:\n  connection refused",
			want: []string{"[ERROR]", "OpenTofu lint failed", "Failed to load plugin:", "connection refused"},
		},
		{
			name:    "long description",
			step:    "lint",
			raw:     "Error: Detailed error\n" + strings.Repeat("More detail about this failure. ", 10),
			want:    []string{"[ERROR]", "Detailed error", "│  More detail"},
			exclude: []string{strings.Repeat("More detail about this failure. ", 10), "│  il\n", "│  s\n"},
		},
		{
			name: "init failure",
			step: "lint init",
			raw:  "Error: Failed to install provider\nNetwork unavailable",
			want: []string{"[ERROR]", "OpenTofu lint init failed", "Failed to install provider", "Network unavailable"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			oldStdout := os.Stdout
			os.Stdout = w
			defer func() { os.Stdout = oldStdout }()
			PrintLintErrorSummary([]TofuMessage{{Step: tc.step, RelPath: "repo/shared", Output: tc.raw}})
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			captured, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			got := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(string(captured), "")
			for _, text := range tc.want {
				if !strings.Contains(got, text) {
					t.Errorf("missing %q:\n%s", text, got)
				}
			}
			for _, text := range tc.exclude {
				if strings.Contains(got, text) {
					t.Errorf("unexpected %q:\n%s", text, got)
				}
			}
			if tc.name == "long description" {
				for _, line := range strings.Split(got, "\n") {
					if strings.HasPrefix(line, "│  ") && len([]rune(line)) > 79 {
						t.Errorf("error text overflowed the card: %q", line)
					}
				}
			}
		})
	}
}
