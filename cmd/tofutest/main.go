package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"tofu-pre-commit-hooks/internal/output"
	"tofu-pre-commit-hooks/internal/testutil"
)

func main() {
	err := RunTofuTestCLI(
		os.Args[1:],
		testutil.CheckOpenTofuInstalled,
		os.Getwd,
		findTestDirs,
		runTofuTest,
		printStatus,
	)
	if err != nil {
		os.Exit(1)
	}
}

// RunTofuTestCLI runs the tofu test CLI logic. Returns error if any step fails.
func RunTofuTestCLI(
	extraArgs []string,
	checkInstalled func() bool,
	getwd func() (string, error),
	findTestDirs func(string) ([]string, error),
	runTest func(string, []string, string) (string, error),
	printStatus func(string, string),
) error {
	if !checkInstalled() {
		fmt.Println("OpenTofu is not installed or not in PATH.")
		return fmt.Errorf("OpenTofu not installed")
	}

	rootDir, err := getwd()
	if err != nil {
		fmt.Println("Could not get working directory.")
		return err
	}

	dirs, err := findTestDirs(rootDir)
	if err != nil {
		fmt.Printf("Error checking for test files: %v\n", err)
		return err
	}

	if len(dirs) == 0 {
		printStatus(output.Running, "No OpenTofu test files (.tftest.hcl) found, skipping tests.")
		return nil
	}

	type testResult struct {
		path   string
		output string
		err    error
	}
	var passed, failed []testResult
	var testErrors []error
	for _, dir := range dirs {
		config, err := readTestConfig(dir)
		var testOutput string
		if err == nil {
			args := append(config.Args, extraArgs...)
			testOutput, err = runTest(dir, args, config.Workspace)
		}
		relPath, relErr := filepath.Rel(rootDir, dir)
		if relErr != nil {
			relPath = dir
		}
		if err != nil {
			testErrors = append(testErrors, fmt.Errorf("%s: %w", relPath, err))
			if strings.TrimSpace(testOutput) == "" {
				testOutput = err.Error()
			}
			failed = append(failed, testResult{relPath, testOutput, err})
		} else {
			passed = append(passed, testResult{relPath, testOutput, nil})
		}
	}

	for _, result := range append(passed, failed...) {
		color, badge, badgeColor := output.Green, "PASS", output.BoldGreen
		if result.err != nil {
			color, badge, badgeColor = output.Red, "FAIL", output.BoldRed
		}
		c := output.NewCard(color)
		c.Open(output.Badge(badge, badgeColor), output.Title("OpenTofu test: "+result.path))
		c.Blank()
		for _, line := range strings.Split(result.output, "\n") {
			if strings.TrimSpace(line) != "" {
				c.Line(fmt.Sprintf("%s%s%s", output.Dim, line, output.Reset))
			}
		}
		c.Close()
		fmt.Println()
	}
	summary := fmt.Sprintf("%d/%d test directories passed", len(passed), len(dirs))
	if len(testErrors) > 0 {
		summary += fmt.Sprintf("  ·  %d failed", len(failed))
		printStatus(output.Error, summary)
		return fmt.Errorf("OpenTofu test failed: %w", errors.Join(testErrors...))
	}
	printStatus(output.ThumbsUp, summary)
	return nil
}

// printStatus prints a colored emoji status message
func printStatus(emoji, msg string) {
	color := output.Green
	if emoji == output.Error {
		color = output.Red
	}
	fmt.Println(output.EmojiColorText(emoji, msg, color))
}

func findTestDirs(rootDir string) ([]string, error) {
	dirs := make(map[string]bool)
	cleanRoot := filepath.Clean(rootDir)
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			name := info.Name()
			if filepath.Clean(path) != cleanRoot && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if strings.HasSuffix(info.Name(), ".tftest.hcl") {
			dir := filepath.Dir(path)
			if filepath.Base(dir) == "tests" && dir != cleanRoot {
				dir = filepath.Dir(dir)
			}
			dirs[dir] = true
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(dirs))
	for dir := range dirs {
		result = append(result, dir)
	}
	slices.Sort(result)
	return result, nil
}

func runTofuTest(dir string, extraArgs []string, workspace string) (string, error) {
	args := append([]string{"test"}, extraArgs...)
	cmd := exec.Command("tofu", args...)
	cmd.Dir = dir
	if workspace != "" {
		cmd.Env = append(cmd.Environ(), "TF_WORKSPACE="+workspace)
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}
