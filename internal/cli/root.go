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

// Package cli wires the devradarctl command tree (urfave/cli v3).
package cli

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/logging"
)

const name = "devradarctl"

// New builds the root command. version/commit/date are injected from main via
// ldflags at build time and surfaced through `--version`.
func New(version, commit, date string) *cli.Command {
	return &cli.Command{
		Name:                  name,
		Usage:                 "Generate and submit SBOMs to DevRadar",
		Version:               fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date),
		EnableShellCompletion: true,
		HideHelpCommand:       true,
		// Suppress urfave/cli's default handler, which calls os.Exit from inside
		// Run (bypassing main's cleanup and breaking tests). main owns the exit
		// code by inspecting the returned error for an ExitCoder.
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Usage:   "enable debug logging (default level is warn)",
				Sources: cli.EnvVars("DEVRADAR_DEBUG"),
			},
			&cli.BoolFlag{
				Name:    "log-json",
				Usage:   "emit logs as JSON instead of text",
				Sources: cli.EnvVars("DEVRADAR_LOG_JSON"),
			},
		},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			logging.Setup(logging.Options{
				Debug:   c.Bool("debug"),
				JSON:    c.Bool("log-json"),
				Version: version,
			})
			return ctx, nil
		},
		Commands: []*cli.Command{
			sbomCmd(),
			submitCmd(),
			imagesCmd(),
			licensesCmd(),
			vexCmd(),
			watchCmd(),
		},
	}
}
