package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tofu-pre-commit-hooks/internal/tofuscan/engine"
	"tofu-pre-commit-hooks/internal/tofuscan/policies"
)

func TestRunTofuScanCLI(t *testing.T) {
	noViolations := &engine.RunResult{Violations: []engine.Violation{}}
	oneViolation := &engine.RunResult{Violations: []engine.Violation{{RuleID: "CIS-1.1", File: "main.tofu", Severity: "High"}}}
	mediumViolation := &engine.RunResult{Violations: []engine.Violation{{RuleID: "CIS-1.2", File: "main.tofu", Severity: "Medium"}}}
	mixedViolations := &engine.RunResult{Violations: []engine.Violation{
		{RuleID: "CIS-1.1", File: "main.tofu", Severity: "High"},
		{RuleID: "CIS-1.2", File: "main.tofu", Severity: "Medium"},
	}}
	noSkips, err := engine.ParseSkipDirectives([]string{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		paths     []string
		warnOnly  bool
		files     []string
		findErr   error
		result    *engine.RunResult
		engineErr error
		skipErr   error
		wantExit  int
		wantErr   bool
	}{
		{
			name:     "no files found",
			paths:    []string{"."},
			files:    []string{},
			wantExit: exitSuccess,
		},
		{
			name:     "find files error",
			paths:    []string{"."},
			findErr:  fmt.Errorf("walk error"),
			wantExit: exitError,
			wantErr:  true,
		},
		{
			name:      "engine error",
			paths:     []string{"."},
			files:     []string{"main.tofu"},
			engineErr: fmt.Errorf("opa error"),
			wantExit:  exitError,
			wantErr:   true,
		},
		{
			name:     "invalid skip fails even with warn-only",
			paths:    []string{"."},
			warnOnly: true,
			files:    []string{"main.tofu"},
			result:   noViolations,
			skipErr:  fmt.Errorf("skip directive requires a reason"),
			wantExit: exitError,
			wantErr:  true,
		},
		{
			name:     "no violations",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   noViolations,
			wantExit: exitSuccess,
		},
		{
			name:     "violations, warn-only false",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   oneViolation,
			wantExit: exitFailure,
		},
		{
			name:     "violations, warn-only true",
			paths:    []string{"."},
			warnOnly: true,
			files:    []string{"main.tofu"},
			result:   oneViolation,
			wantExit: exitSuccess,
		},
		{
			name:     "medium violations do not fail",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   mediumViolation,
			wantExit: exitSuccess,
		},
		{
			name:     "high violations fail alongside medium warnings",
			paths:    []string{"."},
			files:    []string{"main.tofu"},
			result:   mixedViolations,
			wantExit: exitFailure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotExit int
			exitFn := func(code int) { gotExit = code }

			findFiles := func(paths []string) ([]string, error) {
				return tc.files, tc.findErr
			}
			runEngine := func(files []string) (*engine.RunResult, error) {
				return tc.result, tc.engineErr
			}
			printOutput := func(violations []engine.Violation, skipped []engine.Violation, resourceTypes map[string]struct{}) {
			}

			err := RunTofuScanCLI(
				tc.paths,
				tc.warnOnly,
				findFiles,
				runEngine,
				func(files []string) (*engine.SkipDirectives, error) { return noSkips, tc.skipErr },
				printOutput,
				exitFn,
			)

			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if gotExit != tc.wantExit {
				t.Errorf("exit code = %d, want %d", gotExit, tc.wantExit)
			}
		})
	}
}

func TestRunTofuScanCLISkipReasons(t *testing.T) {
	for _, tt := range []struct {
		name        string
		directive   string
		wantErr     bool
		wantSkipped string
	}{
		{name: "reason displayed", directive: "# tofu-scan skip: CIS 5.6.4 - Private access", wantSkipped: "Private access"},
		{name: "missing reason fails with warn-only", directive: "# tofu-scan skip: CIS 5.6.4", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "main.tofu")
			content := "resource \"google_container_cluster\" \"primary\" {\n  " + tt.directive + "\n}\n"
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}

			var exitCode int
			var skipped []engine.Violation
			err := RunTofuScanCLI(
				[]string{path}, true,
				func([]string) ([]string, error) { return []string{path}, nil },
				func([]string) (*engine.RunResult, error) {
					return &engine.RunResult{Violations: []engine.Violation{{
						File: path, Resource: "google_container_cluster.primary", CISControl: "5.6.4", Severity: "High",
					}}}, nil
				},
				engine.ParseSkipDirectives,
				func(_ []engine.Violation, got []engine.Violation, _ map[string]struct{}) { skipped = got },
				func(code int) { exitCode = code },
			)
			if tt.wantErr {
				if err == nil || exitCode != exitError || !strings.Contains(err.Error(), path+":2:") {
					t.Fatalf("expected invalid skip error with location, got error %v and exit %d", err, exitCode)
				}
				return
			}
			if err != nil || exitCode != exitSuccess || len(skipped) != 1 || skipped[0].SkipReason != tt.wantSkipped {
				t.Fatalf("expected skipped reason %q, got skips %+v, error %v, exit %d", tt.wantSkipped, skipped, err, exitCode)
			}
		})
	}
}

func TestRunTofuScanCLIGlobalSkip(t *testing.T) {
	for _, tt := range []struct {
		name      string
		directive string
		wantErr   bool
	}{
		{name: "global finding skipped", directive: "# tofu-scan skip-global: CIS 1.17 - Managed at organization level"},
		{name: "missing reason fails with warn-only", directive: "# tofu-scan skip-global: CIS 1.17", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "main.tofu")
			content := tt.directive + "\nresource \"google_project\" \"this\" {}\n"
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			exitCode := exitSuccess
			var skipped []engine.Violation
			err := RunTofuScanCLI(
				[]string{path}, true,
				func([]string) ([]string, error) { return []string{path}, nil },
				func(files []string) (*engine.RunResult, error) {
					return engine.Run(context.Background(), files, policies.FS)
				},
				engine.ParseSkipDirectives,
				func(_ []engine.Violation, got []engine.Violation, _ map[string]struct{}) { skipped = got },
				func(code int) { exitCode = code },
			)
			if tt.wantErr {
				if err == nil || exitCode != exitError || !strings.Contains(err.Error(), path+":1:") {
					t.Fatalf("expected invalid skip error with location, got error %v and exit %d", err, exitCode)
				}
				return
			}
			if err != nil || exitCode != exitSuccess || len(skipped) != 1 || skipped[0].RuleID != "gcp/cis/1.17" || skipped[0].SkipReason != "Managed at organization level" {
				t.Fatalf("unexpected skips %+v, error %v, exit %d", skipped, err, exitCode)
			}
		})
	}
}
