package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
)

// defaultWatchInterval is the poll cadence when --interval is unset.
const defaultWatchInterval = 30 * time.Second

// watchCmd polls for new change events until interrupted. It targets either one
// SBOM (positional id → events) or one repository (--repo → timeline).
func watchCmd() *cli.Command {
	return &cli.Command{
		Name:      "watch",
		Usage:     "Poll for new change events until interrupted",
		ArgsUsage: "[sbom-id]",
		Description: "Watches either one SBOM (pass <sbom-id>) or one image across digests\n" +
			"(pass --repo). New events are printed as they appear; runs until Ctrl-C.",
		Flags: []cli.Flag{
			baseURLFlag(),
			&cli.StringFlag{Name: flagRepo, Usage: "repository to watch (mutually exclusive with <sbom-id>)"},
			&cli.StringFlag{Name: flagMinSeverity, Usage: "minimum severity floor"},
			&cli.DurationFlag{Name: flagInterval, Value: defaultWatchInterval, Usage: "poll interval"},
		},
		Action: runWatch,
	}
}

func runWatch(ctx context.Context, c *cli.Command) error {
	id := c.Args().First()
	repo := c.String(flagRepo)
	switch {
	case id == "" && repo == "":
		return errors.New("one of <sbom-id> or --repo is required")
	case id != "" && repo != "":
		return errors.New("<sbom-id> and --repo are mutually exclusive")
	}

	cl, err := apiClient(c)
	if err != nil {
		return err
	}
	minSev := c.String(flagMinSeverity)

	// poll fetches the newest events and returns them oldest-first so printing
	// preserves chronological order.
	poll := func(ctx context.Context) ([]watchRow, error) {
		if repo != "" {
			pg, err := cl.Timeline(ctx, repo, client.ListOptions{MinSeverity: minSev})
			if err != nil {
				return nil, err
			}
			return timelineRows(pg.Timeline), nil
		}
		pg, err := cl.Events(ctx, id, client.ListOptions{MinSeverity: minSev})
		if err != nil {
			return nil, err
		}
		return eventRows(pg.Events), nil
	}

	seen := map[string]bool{}
	// Prime with the current state so we only print events that arrive after the
	// watch starts; mark existing ones seen without printing.
	rows, err := poll(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		seen[r.key] = true
	}
	fmt.Fprintf(c.Writer, "watching %s (interval %s); press Ctrl-C to stop\n", watchTarget(id, repo), c.Duration(flagInterval))

	ticker := time.NewTicker(c.Duration(flagInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rows, err := poll(ctx)
			if err != nil {
				// Transient poll errors shouldn't kill a long-running watch;
				// surface and keep going unless the context was cancelled.
				if ctx.Err() != nil {
					return nil
				}
				fmt.Fprintf(c.ErrWriter, "poll error: %v\n", err)
				continue
			}
			for _, r := range rows {
				if !seen[r.key] {
					seen[r.key] = true
					fmt.Fprintln(c.Writer, r.line)
				}
			}
		}
	}
}

func watchTarget(id, repo string) string {
	if repo != "" {
		return "repo " + repo
	}
	return "sbom " + id
}

// watchRow is a de-duplicatable, printable event line.
type watchRow struct {
	key  string
	line string
}

func eventRows(events []client.Event) []watchRow {
	rows := make([]watchRow, 0, len(events))
	// API returns newest-first; reverse to print chronologically.
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		key := fmt.Sprintf("%s|%s|%s|%s", e.OccurredAt, e.EventType, e.Exposure, e.Package)
		line := fmt.Sprintf("%s  %-8s %-9s %s %s (%s)", e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, e.Cause)
		rows = append(rows, watchRow{key: key, line: line})
	}
	return rows
}

func timelineRows(events []client.TimelineEvent) []watchRow {
	rows := make([]watchRow, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		key := fmt.Sprintf("%s|%s|%s|%s|%s", e.OccurredAt, e.EventType, e.Exposure, e.Package, e.Digest)
		line := fmt.Sprintf("%s  %-8s %-9s %s %s [%s]", e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, shortDigest(e.Digest))
		rows = append(rows, watchRow{key: key, line: line})
	}
	return rows
}
