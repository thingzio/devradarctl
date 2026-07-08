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
		},
	}
}
