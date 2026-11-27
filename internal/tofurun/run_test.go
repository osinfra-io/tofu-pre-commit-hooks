package tofurun

import (
	"errors"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		jobs     int
		skipInit bool
		extra    []string
		wantErr  bool
	}{
		{name: "default"},
		{name: "equals", args: []string{"-no-color", "--jobs=2", "--skip-init"}, jobs: 2, skipInit: true, extra: []string{"-no-color"}},
		{name: "split and tofu values", args: []string{"--jobs", "1", "-var", "message=value"}, jobs: 1, extra: []string{"-var", "message=value"}},
		{name: "hook-like tofu values", args: []string{"-var-file", "--jobs=2", "--filter", "--skip-init", "--jobs=3"}, jobs: 3, extra: []string{"-var-file", "--jobs=2", "--filter", "--skip-init"}},
		{name: "equals-form tofu flag", args: []string{"-var-file=vars.tfvars", "--jobs=2"}, jobs: 2, extra: []string{"-var-file=vars.tfvars"}},
		{name: "end of options", args: []string{"--jobs=2", "--", "--jobs=3", "--skip-init"}, jobs: 2, extra: []string{"--", "--jobs=3", "--skip-init"}},
		{name: "end marker as tofu value", args: []string{"-var-file", "--", "--jobs=2"}, jobs: 2, extra: []string{"-var-file", "--"}},
		{name: "missing jobs", args: []string{"--jobs"}, wantErr: true},
		{name: "empty jobs", args: []string{"--jobs="}, wantErr: true},
		{name: "zero jobs", args: []string{"--jobs=0"}, wantErr: true},
		{name: "negative jobs", args: []string{"--jobs=-1"}, wantErr: true},
		{name: "invalid jobs", args: []string{"--jobs", "many"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options, extra, err := ParseArgs(tc.args)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if tc.jobs == 0 {
				if want := min(8, runtime.GOMAXPROCS(0)); options.Jobs != want {
					t.Errorf("default jobs = %d, want %d", options.Jobs, want)
				}
			} else if options.Jobs != tc.jobs {
				t.Errorf("jobs = %d, want %d", options.Jobs, tc.jobs)
			}
			if options.SkipInit != tc.skipInit || !reflect.DeepEqual(extra, tc.extra) {
				t.Errorf("SkipInit = %v, extra = %v; want %v, %v", options.SkipInit, extra, tc.skipInit, tc.extra)
			}
		})
	}
}

func TestRunConcurrencyAndOrdering(t *testing.T) {
	dirs := []string{"a", "b", "c", "d"}
	started := make(chan string, len(dirs))
	release := make(chan struct{})
	defer close(release)
	done := make(chan []Result, 1)
	go func() {
		done <- Run(dirs, Options{Jobs: 2},
			func(string) (string, error) { return "", nil },
			func(dir string) (string, error) {
				started <- dir
				<-release
				return dir, nil
			},
		)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("checks did not run concurrently")
		}
	}
	select {
	case dir := <-started:
		t.Fatalf("worker limit exceeded by %s", dir)
	default:
	}
	// Release the first pair and leave the channel open for the second pair.
	release <- struct{}{}
	release <- struct{}{}
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("remaining directories were not checked")
		}
	}
	release <- struct{}{}
	release <- struct{}{}
	select {
	case results := <-done:
		for i, result := range results {
			if result.Output != dirs[i] || result.Err != nil || result.InitFailed {
				t.Errorf("result[%d] = %+v, want successful %s", i, result, dirs[i])
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("directory runner did not finish")
	}
}

func TestRunSerializesInit(t *testing.T) {
	var active atomic.Int32
	var overlapping atomic.Bool
	dirs := make([]string, 20)
	Run(dirs, Options{Jobs: 4},
		func(string) (string, error) {
			if active.Add(1) != 1 {
				overlapping.Store(true)
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
			return "", nil
		},
		func(string) (string, error) { return "", nil },
	)
	if overlapping.Load() {
		t.Fatal("initializations overlapped")
	}
}

func TestRunErrorsAndSkipInit(t *testing.T) {
	initErr := errors.New("init failed")
	checkErr := errors.New("validation failed")
	for _, skipInit := range []bool{false, true} {
		results := Run([]string{"init-error", "check-error", "ok"}, Options{Jobs: 3, SkipInit: skipInit},
			func(dir string) (string, error) {
				if skipInit {
					t.Error("init called with SkipInit enabled")
				}
				if dir == "init-error" {
					return "", initErr
				}
				return "", nil
			},
			func(dir string) (string, error) {
				if dir == "init-error" && !skipInit {
					t.Error("validation called after init failed")
				}
				if dir == "check-error" {
					return "", checkErr
				}
				return dir, nil
			},
		)
		if !skipInit && (!results[0].InitFailed || !errors.Is(results[0].Err, initErr) || results[0].Output != initErr.Error()) {
			t.Errorf("init failure lost: %+v", results[0])
		}
		if skipInit && (results[0].InitFailed || results[0].Err != nil) {
			t.Errorf("SkipInit result = %+v", results[0])
		}
		if !errors.Is(results[1].Err, checkErr) || results[1].Output != checkErr.Error() || results[1].InitFailed {
			t.Errorf("validation failure lost: %+v", results[1])
		}
		if results[2].Err != nil || results[2].Output != "ok" {
			t.Errorf("independent directory was not checked: %+v", results[2])
		}
	}
}
