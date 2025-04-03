package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "log/slog"

	"github.com/alecthomas/kingpin"
	"github.com/prometheus/procfs"
)

var (
	app          = kingpin.New("allproc", "reads all processes from /proc to get procsess cpu usage")
	loopInterval = app.Flag("loop-interval", "loop interval").Default("1000ms").Duration()
	enablePprof  = app.Flag("enable-pprof", "enable profiling with pprof").Default("false").Bool()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))
	// Subscribe to signals for terminating the program
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		cancel()
	}()
	if *enablePprof {
		setupPprof()
	}

	doneCh := make(chan struct{})
	go run(ctx, doneCh)

	<-ctx.Done()
	log.Info("received Ctrl-C.")
	<-doneCh
	log.Info("Shutting down...")
}

func run(ctx context.Context, doneCh chan struct{}) {
	log.Info("Starting loop", "interval", loopInterval)
	ticker := time.Tick(*loopInterval)
	oldTs := time.Now()

	for {
		select {
		case newTs := <-ticker:
			timeDiffSec := newTs.Sub(oldTs).Seconds()
			if timeDiffSec < 0.1 {
				continue
			}
			// get all procs
			allProcs, err := procfs.AllProcs()
			if err != nil {
				log.Error("cannot read AllProcs")
			}
			// read /proc/<pid>/stat for each
			for _, proc := range allProcs {
				// deliberately ignoring the returned stat object
				_, err := proc.Stat()
				if err != nil {
					log.Error("cannot read stat for pid", "pid", proc.PID)
				}
			}
			log.Info("AllProcs", "num", len(allProcs), "cost", time.Since(newTs).String())

		case <-ctx.Done():
			log.Info("loop finished...")
			close(doneCh)
			return
		}
	}
}

func setupPprof() {
	go func() {
		http.ListenAndServe(":6060", http.DefaultServeMux)
	}()
}
