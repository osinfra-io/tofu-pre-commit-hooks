package tofurun

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type Options struct {
	Jobs     int
	SkipInit bool
}

// ParseArgs removes hook options while preserving OpenTofu arguments and values.
func ParseArgs(args []string) (Options, []string, error) {
	options := Options{Jobs: min(4, runtime.GOMAXPROCS(0))}
	var extraArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--skip-init":
			options.SkipInit = true
		case arg == "--jobs" || strings.HasPrefix(arg, "--jobs="):
			value, equals := strings.CutPrefix(arg, "--jobs=")
			if !equals {
				i++
				if i == len(args) {
					return Options{}, nil, fmt.Errorf("--jobs requires a positive integer")
				}
				value = args[i]
			}
			jobs, err := strconv.Atoi(value)
			if err != nil || jobs < 1 {
				return Options{}, nil, fmt.Errorf("--jobs requires a positive integer, got %q", value)
			}
			options.Jobs = jobs
		default:
			extraArgs = append(extraArgs, arg)
		}
	}
	return options, extraArgs, nil
}

type Result struct {
	Output     string
	Err        error
	InitFailed bool
}

// Run checks directories concurrently but keeps initialization serial because
// OpenTofu initializations can write to the same shared provider cache.
// Results retain the input directory order for deterministic diagnostics.
func Run(
	dirs []string,
	options Options,
	init func(string) (string, error),
	check func(string) (string, error),
) []Result {
	results := make([]Result, len(dirs))
	var initMu sync.Mutex
	var workers sync.WaitGroup
	work := make(chan int)
	for range min(options.Jobs, len(dirs)) {
		workers.Go(func() {
			for i := range work {
				var result Result
				if !options.SkipInit {
					initMu.Lock()
					result.Output, result.Err = init(dirs[i])
					initMu.Unlock()
					result.InitFailed = result.Err != nil
				}
				if !result.InitFailed {
					result.Output, result.Err = check(dirs[i])
				}
				if result.Err != nil && strings.TrimSpace(result.Output) == "" {
					result.Output = result.Err.Error()
				}
				results[i] = result
			}
		})
	}
	for i := range dirs {
		work <- i
	}
	close(work)
	workers.Wait()
	return results
}
