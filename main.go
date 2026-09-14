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
	"runtime/debug"
	"syscall"

	"github.com/urfave/cli/v3"

	devcli "github.com/thingzio/devradarctl/internal/cli"
)

// Placeholders for a build that carried no -ldflags.
const (
	devVersion = "dev"
	devCommit  = "none"
	devDate    = "unknown"
)

// Injected via -ldflags at build time; see resolveBuildInfo for the fallback.
var (
	version = devVersion
	commit  = devCommit
	date    = devDate
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bi, _ := debug.ReadBuildInfo()
	v, c, d := resolveBuildInfo(version, commit, date, bi)

	err := devcli.New(v, c, d).Run(ctx, os.Args)
	return exitCode(os.Stderr, err)
}

// resolveBuildInfo backfills any placeholder left by a build that carried no
// -ldflags from the binary's embedded build info. `go install <module>@<ver>`
// -- a documented install path -- sets no ldflags, so without this the CLI
// reports "dev (commit: none, date: unknown)" for a real tagged release.
// Values that were injected are never overwritten: the ldflags are the more
// precise source (goreleaser stamps the release tag, the module version can be
// a pseudo-version).
func resolveBuildInfo(v, c, d string, bi *debug.BuildInfo) (string, string, string) {
	if bi == nil {
		return v, c, d
	}

	// A local `go build` reports "(devel)", which is less informative than "dev".
	if v == devVersion && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		v = bi.Main.Version
	}

	var revision, buildTime string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			buildTime = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}

	if c == devCommit && revision != "" {
		c = shortCommit(revision)
		if dirty {
			c += "-dirty"
		}
	}
	if d == devDate && buildTime != "" {
		d = buildTime
	}

	return v, c, d
}

// shortCommit abbreviates a revision to the 7 characters `git rev-parse
// --short` and goreleaser's .ShortCommit produce, so both build paths render
// the same way.
func shortCommit(revision string) string {
	const short = 7
	if len(revision) <= short {
		return revision
	}
	return revision[:short]
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
