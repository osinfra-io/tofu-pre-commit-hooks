package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"tofu-pre-commit-hooks/internal/output"
	"tofu-pre-commit-hooks/internal/testutil"
)

func TestRunTofuTestCLI_TofuNotInstalled(t *testing.T) {
	checkInstalled := func() bool { return false }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return []string{"/fake"}, nil }
	runTest := func(string, []string, string) (string, error) { return "", nil }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err == nil {
		t.Error("Expected error when tofu not installed, got nil")
	}
}

func TestRunTofuTestCLI_GetwdError(t *testing.T) {
	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "", errors.New("getwd failed") }
	findTestDirs := func(string) ([]string, error) { return []string{"/fake"}, nil }
	runTest := func(string, []string, string) (string, error) { return "", nil }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err == nil {
		t.Error("Expected error when getwd fails, got nil")
	}
}

func TestRunTofuTestCLI_NoTestFiles(t *testing.T) {
	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return nil, nil }
	runTest := func(string, []string, string) (string, error) { return "", nil }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err != nil {
		t.Errorf("Expected no error when no test files, got %v", err)
	}
}

func TestRunTofuTestCLI_HasTestFilesError(t *testing.T) {
	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return nil, errors.New("walk error") }
	runTest := func(string, []string, string) (string, error) { return "", nil }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err == nil {
		t.Error("Expected error when hasTestFiles fails, got nil")
	}
}

func TestRunTofuTestCLI_TestSuccess(t *testing.T) {
	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return []string{"/fake"}, nil }
	runTest := func(string, []string, string) (string, error) { return "All tests passed", nil }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err != nil {
		t.Errorf("Expected no error when tests pass, got %v", err)
	}
}

func TestRunTofuTestCLI_TestFailure(t *testing.T) {
	rootCause := errors.New("test error")

	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return []string{"/fake"}, nil }
	runTest := func(string, []string, string) (string, error) { return "Test failed", rootCause }
	printStatus := func(string, string) {}

	err := RunTofuTestCLI(nil, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err == nil {
		t.Error("Expected error when tests fail, got nil")
	}
	if !errors.Is(err, rootCause) {
		t.Errorf("Expected returned error to wrap root cause, got: %v", err)
	}
}

func TestRunTofuTestCLI_ExtraArgs(t *testing.T) {
	var receivedArgs []string

	checkInstalled := func() bool { return true }
	getwd := func() (string, error) { return "/fake", nil }
	findTestDirs := func(string) ([]string, error) { return []string{"/fake"}, nil }
	runTest := func(dir string, args []string, workspace string) (string, error) {
		receivedArgs = args
		return "Tests passed", nil
	}
	printStatus := func(string, string) {}

	extraArgs := []string{"-verbose", "-filter=TestFoo"}
	err := RunTofuTestCLI(extraArgs, checkInstalled, getwd, findTestDirs, runTest, printStatus)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if len(receivedArgs) != 2 {
		t.Errorf("Expected 2 args, got %d", len(receivedArgs))
	}
	if len(receivedArgs) > 0 && receivedArgs[0] != "-verbose" {
		t.Errorf("Expected first arg to be -verbose, got %s", receivedArgs[0])
	}
	if len(receivedArgs) > 1 && receivedArgs[1] != "-filter=TestFoo" {
		t.Errorf("Expected second arg to be -filter=TestFoo, got %s", receivedArgs[1])
	}
}

func TestRunTofuTestCLI_RunsEveryDirectoryAfterFailure(t *testing.T) {
	rootCause := errors.New("test failed")
	dirs := []string{"/fake/a", "/fake/b"}
	var visited []string
	err := RunTofuTestCLI(
		[]string{"-verbose"},
		func() bool { return true },
		func() (string, error) { return "/fake", nil },
		func(string) ([]string, error) { return dirs, nil },
		func(dir string, args []string, workspace string) (string, error) {
			visited = append(visited, dir)
			if !reflect.DeepEqual(args, []string{"-verbose"}) {
				t.Errorf("unexpected arguments: %v", args)
			}
			if dir == dirs[0] {
				return "", rootCause
			}
			return "passed", nil
		},
		func(string, string) {},
	)
	if !errors.Is(err, rootCause) {
		t.Errorf("expected test failure, got %v", err)
	}
	if !reflect.DeepEqual(visited, dirs) {
		t.Errorf("visited %v, want %v", visited, dirs)
	}
}

func TestRunTofuTestCLI_ReportsPassingDirectoriesBeforeFailures(t *testing.T) {
	root := t.TempDir()
	var dirs []string
	for _, name := range []string{"a-fail", "b-pass", "c-invalid", "d-pass", "e-fail"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, dir)
	}
	if err := os.WriteFile(filepath.Join(dirs[2], ".tofu-test.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			t.Errorf("close output: %v", err)
		}
	}()
	originalStdout := os.Stdout
	os.Stdout = out
	defer func() { os.Stdout = originalStdout }()

	var emoji, summary string
	runErr := RunTofuTestCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return root, nil },
		func(string) ([]string, error) { return dirs, nil },
		func(dir string, _ []string, _ string) (string, error) {
			if strings.HasSuffix(dir, "-fail") {
				return "test failure details", errors.New("test failure")
			}
			return "test passed", nil
		},
		func(e, msg string) { emoji, summary = e, msg },
	)
	if runErr == nil {
		t.Fatal("expected failures")
	}
	if emoji != output.Error || summary != "2/5 test directories passed  ·  3 failed" {
		t.Errorf("summary = %q %q", emoji, summary)
	}
	data, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	text := ansi.Strip(string(data))
	last := -1
	for _, expected := range []string{
		"[PASS] OpenTofu test: b-pass", "[PASS] OpenTofu test: d-pass",
		"[FAIL] OpenTofu test: a-fail", "[FAIL] OpenTofu test: c-invalid", "[FAIL] OpenTofu test: e-fail",
	} {
		pos := strings.Index(text, expected)
		if pos <= last {
			t.Fatalf("missing or out-of-order %q in:\n%s", expected, text)
		}
		last = pos
	}
	if !strings.Contains(text, "test failure details") || !strings.Contains(text, "invalid configuration") {
		t.Errorf("expected test and configuration diagnostics in:\n%s", text)
	}
}

func TestRunTofuTestCLI_SuccessSummary(t *testing.T) {
	var emoji, summary string
	err := RunTofuTestCLI(
		nil,
		func() bool { return true },
		func() (string, error) { return "/fake", nil },
		func(string) ([]string, error) { return []string{"/fake/a", "/fake/b"}, nil },
		func(string, []string, string) (string, error) { return "passed", nil },
		func(e, msg string) { emoji, summary = e, msg },
	)
	if err != nil || emoji != output.ThumbsUp || summary != "2/2 test directories passed" {
		t.Errorf("result = %v, %q %q", err, emoji, summary)
	}
}

func TestFindTestDirs_ModuleLayouts(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"root.tftest.hcl", "tests/root.tftest.hcl",
		"modules/a/tests/first.tftest.hcl", "modules/a/tests/second.tftest.hcl",
		"modules/b/direct.tftest.hcl", "tests/integration/app/runtime.tftest.hcl",
		".terraform/modules/c/tests/ignored.tftest.hcl",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findTestDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{root, filepath.Join(root, "modules/a"), filepath.Join(root, "modules/b"), filepath.Join(root, "tests/integration/app")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findTestDirs() = %v, want %v", got, want)
	}
}

func TestHasTestFiles_WithTestFiles(t *testing.T) {
	tempDir, cleanup := testutil.CreateTempDir(t, "tofutest-has-test")
	defer cleanup()

	testFile := filepath.Join(tempDir, "example.tftest.hcl")
	if err := os.WriteFile(testFile, []byte("# test file"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	got, err := findTestDirs(tempDir)
	if err != nil {
		t.Fatalf("hasTestFiles() returned error: %v", err)
	}
	if len(got) == 0 {
		t.Error("hasTestFiles() = false, want true when test file exists")
	}
}

func TestHasTestFiles_WithoutTestFiles(t *testing.T) {
	tempDir, cleanup := testutil.CreateTempDir(t, "tofutest-no-test")
	defer cleanup()

	tfFile := filepath.Join(tempDir, "main.tf")
	if err := os.WriteFile(tfFile, []byte("# tf file"), 0o644); err != nil {
		t.Fatalf("Failed to create tf file: %v", err)
	}

	got, err := findTestDirs(tempDir)
	if err != nil {
		t.Fatalf("hasTestFiles() returned error: %v", err)
	}
	if len(got) != 0 {
		t.Error("hasTestFiles() = true, want false when no test files exist")
	}
}

func TestHasTestFiles_InSubdirectory(t *testing.T) {
	tempDir, cleanup := testutil.CreateTempDir(t, "tofutest-subdir")
	defer cleanup()

	subDir := filepath.Join(tempDir, "tests")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	testFile := filepath.Join(subDir, "integration.tftest.hcl")
	if err := os.WriteFile(testFile, []byte("# test file in subdir"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	got, err := findTestDirs(tempDir)
	if err != nil {
		t.Fatalf("hasTestFiles() returned error: %v", err)
	}
	if len(got) == 0 {
		t.Error("hasTestFiles() = false, want true when test file exists in subdirectory")
	}
}

func TestHasTestFiles_SkipsHiddenDirectories(t *testing.T) {
	tempDir, cleanup := testutil.CreateTempDir(t, "tofutest-hidden")
	defer cleanup()

	hiddenDir := filepath.Join(tempDir, ".hidden")
	if err := os.Mkdir(hiddenDir, 0o755); err != nil {
		t.Fatalf("Failed to create hidden directory: %v", err)
	}

	testFile := filepath.Join(hiddenDir, "test.tftest.hcl")
	if err := os.WriteFile(testFile, []byte("# test file in hidden dir"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	got, err := findTestDirs(tempDir)
	if err != nil {
		t.Fatalf("hasTestFiles() returned error: %v", err)
	}
	if len(got) != 0 {
		t.Error("hasTestFiles() = true, want false when test files only in hidden directories")
	}
}
