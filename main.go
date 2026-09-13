// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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
