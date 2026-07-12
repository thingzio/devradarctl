package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
)

// baseURLFlag returns a fresh --base-url flag for API commands.
func baseURLFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    flagBaseURL,
		Usage:   "DevRadar service base URL",
		Value:   client.DefaultBaseURL,
		Sources: cli.EnvVars("DEVRADAR_BASE_URL"),
	}
}

// listFlags returns the shared paging/severity flags for list commands.
func listFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: flagMinSeverity, Usage: "minimum severity floor: critical|high|medium|low|negligible"},
		&cli.StringFlag{Name: flagSort, Usage: "sort key (endpoint-specific)"},
		&cli.StringFlag{Name: flagDir, Usage: "sort direction: asc|desc"},
		&cli.IntFlag{Name: flagLimit, Usage: "max rows per page (1–1000, default 100)"},
		&cli.BoolFlag{Name: flagAll, Usage: "fetch every page (table output; JSON always includes all)"},
	}
}

// apiClient resolves the API token (env or piped stdin) and returns a client
// bound to the configured base URL.
func apiClient(c *cli.Command) (*client.Client, error) {
	token, err := resolveToken(c.Reader)
	if err != nil {
		return nil, err
	}
	return client.New(c.String(flagBaseURL), token), nil
}

// firstArg returns the first positional argument, or an error naming what was
// expected when none was given.
func firstArg(c *cli.Command, what string) (string, error) {
	if v := c.Args().First(); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%s is required", what)
}

// listOptions builds client.ListOptions from the shared list flags. Cursor is
// set by the paging loop, not a flag.
func listOptions(c *cli.Command) client.ListOptions {
	return client.ListOptions{
		MinSeverity: c.String(flagMinSeverity),
		Sort:        c.String(flagSort),
		Dir:         c.String(flagDir),
		Limit:       c.Int(flagLimit),
	}
}

func sbomGetCmd() *cli.Command {
	return &cli.Command{
		Name:      "get",
		Usage:     "Show metadata and severity breakdown for an SBOM",
		ArgsUsage: "<sbom-id>",
		Flags: []cli.Flag{
			baseURLFlag(), outputFlag(),
			&cli.StringFlag{Name: flagMinSeverity, Usage: "minimum severity floor for the breakdown"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			id, err := firstArg(c, "sbom-id")
			if err != nil {
				return err
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			d, err := cl.GetSBOM(ctx, id, c.String(flagMinSeverity))
			if err != nil {
				return err
			}
			return render(c, d, func(w io.Writer) {
				fmt.Fprintf(w, "SBOM\t%s\n", d.SBOMID)
				fmt.Fprintf(w, "Image\t%s\n", d.ImageRef)
				fmt.Fprintf(w, "Digest\t%s\n", d.Digest)
				fmt.Fprintf(w, "Format\t%s (%s)\n", d.Format, d.SpecVersion)
				fmt.Fprintf(w, "Tool\t%s %s\n", d.Tool, d.ToolVersion)
				fmt.Fprintf(w, "Status\t%s\n", d.Status)
				fmt.Fprintf(w, "Verification\t%s\n", d.VerificationStatus)
				fmt.Fprintf(w, "Generated\t%s\n", d.GeneratedAt)
				fmt.Fprintf(w, "Submitted\t%s\n", d.SubmittedAt)
				fmt.Fprintf(w, "Severity\t%s\n", severitySummary(d.Counts))
			})
		},
	}
}

func sbomFindingsCmd() *cli.Command {
	return &cli.Command{
		Name:      "findings",
		Usage:     "List current vulnerability findings for an SBOM",
		ArgsUsage: "<sbom-id>",
		Description: "Prints findings at or above --min-severity. With --exit-code, exits\n" +
			"non-zero when a threshold is breached (for CI gates):\n" +
			"  --fail-on <severity>  fail if any finding at or above this severity exists\n" +
			"  --max-critical/-high/-medium N  fail if the count exceeds N\n" +
			"Exit code is 2 when a threshold is breached, 0 otherwise.",
		Flags: append(listFlags(),
			baseURLFlag(), outputFlag(),
			&cli.BoolFlag{Name: flagFixable, Usage: "only findings with a fix available"},
			&cli.BoolFlag{Name: flagSuppressed, Usage: "include VEX-suppressed findings"},
			&cli.BoolFlag{Name: flagExitCode, Usage: "exit non-zero when a threshold is breached"},
			&cli.StringFlag{Name: flagFailOn, Usage: "fail if any finding at or above this severity exists"},
			&cli.IntFlag{Name: flagMaxCritical, Value: -1, Usage: "fail if critical count exceeds N"},
			&cli.IntFlag{Name: flagMaxHigh, Value: -1, Usage: "fail if high count exceeds N"},
			&cli.IntFlag{Name: flagMaxMedium, Value: -1, Usage: "fail if medium count exceeds N"},
		),
		Action: runFindings,
	}
}

func sbomEventsCmd() *cli.Command {
	return &cli.Command{
		Name:      "events",
		Usage:     "Show the change log for an SBOM",
		ArgsUsage: "<sbom-id>",
		Flags:     append(listFlags(), baseURLFlag(), outputFlag()),
		Action: func(ctx context.Context, c *cli.Command) error {
			id, err := firstArg(c, "sbom-id")
			if err != nil {
				return err
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			all := c.Bool(flagAll)
			var events []client.Event
			opts := listOptions(c)
			for {
				pg, err := cl.Events(ctx, id, opts)
				if err != nil {
					return err
				}
				events = append(events, pg.Events...)
				if pg.NextCursor == "" || (!all && !asJSON(c)) {
					if err := render(c, events, func(w io.Writer) { eventTable(w, events) }); err != nil {
						return err
					}
					moreHint(pg.NextCursor, all)
					return nil
				}
				opts.Cursor = pg.NextCursor
			}
		},
	}
}

func sbomFailuresCmd() *cli.Command {
	return &cli.Command{
		Name:      "failures",
		Usage:     "Show recent scan failures for an SBOM",
		ArgsUsage: "<sbom-id>",
		Flags: []cli.Flag{
			baseURLFlag(), outputFlag(),
			&cli.IntFlag{Name: flagLimit, Usage: "max rows"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			id, err := firstArg(c, "sbom-id")
			if err != nil {
				return err
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			fs, err := cl.Failures(ctx, id, c.Int(flagLimit))
			if err != nil {
				return err
			}
			return render(c, fs, func(w io.Writer) {
				fmt.Fprintln(w, "SCANNER\tSTAGE\tOCCURRED\tERROR")
				for _, f := range fs {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Scanner, f.Stage, f.OccurredAt, f.Error)
				}
			})
		},
	}
}

func sbomLicensesCmd() *cli.Command {
	return &cli.Command{
		Name:      "licenses",
		Usage:     "List package licenses and policy verdicts for an SBOM",
		ArgsUsage: "<sbom-id>",
		Flags:     []cli.Flag{baseURLFlag(), outputFlag()},
		Action: func(ctx context.Context, c *cli.Command) error {
			id, err := firstArg(c, "sbom-id")
			if err != nil {
				return err
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			pkgs, err := cl.Licenses(ctx, id)
			if err != nil {
				return err
			}
			return render(c, pkgs, func(w io.Writer) {
				fmt.Fprintln(w, "PACKAGE\tVERSION\tCATEGORY\tLICENSES\tVIOLATION")
				for _, p := range pkgs {
					v := ""
					if p.Violation {
						v = "yes: " + p.Reason
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Package, p.Version, p.Category, joinList(p.Licenses), v)
				}
			})
		},
	}
}

func sbomArchiveCmd() *cli.Command {
	return &cli.Command{
		Name:      "archive",
		Usage:     "Stop tracking an SBOM (idempotent; history retained)",
		ArgsUsage: "<sbom-id>",
		Flags: []cli.Flag{
			baseURLFlag(),
			&cli.BoolFlag{Name: flagYes, Aliases: []string{"y"}, Usage: "skip the confirmation prompt"},
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			id, err := firstArg(c, "sbom-id")
			if err != nil {
				return err
			}
			if !c.Bool(flagYes) {
				if !confirm(c.Reader, c.Writer, fmt.Sprintf("Archive SBOM %s? This removes it from the scan set. [y/N] ", id)) {
					return errors.New("aborted")
				}
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			if err := cl.ArchiveSBOM(ctx, id); err != nil {
				return err
			}
			fmt.Fprintf(c.Writer, "archived %s\n", id)
			return nil
		},
	}
}
