// Command devradarctl is the CLI for the DevRadar service: it generates
// container-image SBOMs and submits them to a DevRadar instance.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	devcli "github.com/thingzio/devradarctl/internal/cli"
)

// Injected via -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := devcli.New(version, commit, date).Run(ctx, os.Args)
	return exitCode(os.Stderr, err)
}

// exitCode maps a Run error to a process exit code, printing to w. It is split
// out from run so the mapping can be unit-tested without spawning a process.
func exitCode(w io.Writer, err error) int {
	if err == nil {
		return 0
	}
	// An ExitCoder (e.g. the findings CI gate) carries its own code and has
	// already printed any message it wanted; honor it without re-printing.
	if ec, ok := errors.AsType[cli.ExitCoder](err); ok {
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(w, "error: "+msg)
		}
		return ec.ExitCode()
	}
	fmt.Fprintln(w, "error: "+err.Error())
	return 1
}
