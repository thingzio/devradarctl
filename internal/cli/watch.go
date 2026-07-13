package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
)

const (
	// defaultWatchInterval is the poll cadence when --interval is unset.
	defaultWatchInterval = 30 * time.Second
	// minWatchInterval floors the poll cadence: below this we hammer the API for
	// no benefit, and a non-positive value would panic time.NewTicker.
	minWatchInterval = time.Second
	// maxSeenKeys bounds the dedup set so a long-running watch can't grow memory
	// without limit. Oldest keys are evicted first (FIFO); the watermark ensures
	// evicted-but-still-relevant events are never re-fetched to begin with.
	maxSeenKeys = 8192
	// maxPagesPerPoll bounds pagination per tick so a huge backlog (or a cursor
	// bug) can't make one poll run unbounded.
	maxPagesPerPoll = 50
)

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
	if sev := c.String(flagMinSeverity); sev != "" && !validSeverities[sev] {
		return fmt.Errorf("invalid --min-severity %q: want one of critical|high|medium|low|negligible", sev)
	}
	interval := c.Duration(flagInterval)
	if interval < minWatchInterval {
		return fmt.Errorf("invalid --interval %s: must be >= %s", interval, minWatchInterval)
	}

	cl, err := apiClient(c)
	if err != nil {
		return err
	}
	minSev := c.String(flagMinSeverity)

	// fetchPage returns one page of rows (newest-first) plus the next cursor.
	fetchPage := func(ctx context.Context, cursor string) ([]watchRow, string, error) {
		opts := client.ListOptions{MinSeverity: minSev, Cursor: cursor}
		if repo != "" {
			pg, err := cl.Timeline(ctx, repo, opts)
			if err != nil {
				return nil, "", err
			}
			return timelineRows(pg.Timeline), pg.NextCursor, nil
		}
		pg, err := cl.Events(ctx, id, opts)
		if err != nil {
			return nil, "", err
		}
		return eventRows(pg.Events), pg.NextCursor, nil
	}

	w := newWatcher()
	// Prime with current state so only events arriving after the watch starts are
	// printed. Priming records existing keys as seen without emitting them.
	if _, err := w.poll(ctx, fetchPage); err != nil {
		return err
	}
	fmt.Fprintf(c.Writer, "watching %s (interval %s); press Ctrl-C to stop\n", watchTarget(id, repo), interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fresh, err := w.poll(ctx, fetchPage)
			if err != nil {
				// Transient poll errors shouldn't kill a long-running watch;
				// surface and keep going unless the context was cancelled.
				if ctx.Err() != nil {
					return nil
				}
				fmt.Fprintf(c.ErrWriter, "poll error: %v\n", err)
				continue
			}
			for _, r := range fresh {
				fmt.Fprintln(c.Writer, r.line)
			}
		}
	}
}

// watcher tracks which events have already been emitted. It uses a high-water
// timestamp to bound how far each poll paginates, and a FIFO-capped key set to
// deduplicate events sharing (or lacking a parseable) timestamp — so memory
// stays bounded no matter how long the watch runs.
type watcher struct {
	watermark time.Time // newest OccurredAt emitted; zero until first poll
	seen      map[string]struct{}
	order     []string // insertion order for FIFO eviction
}

func newWatcher() *watcher {
	return &watcher{seen: make(map[string]struct{})}
}

// poll fetches pages newest-first until a page is entirely older than the
// watermark (everything beyond is older still), then returns the not-yet-seen
// rows in chronological (oldest-first) order. The first call primes state and
// returns the initial rows as "fresh"; callers that want priming to be silent
// simply discard that first result.
func (w *watcher) poll(ctx context.Context, fetchPage func(context.Context, string) ([]watchRow, string, error)) ([]watchRow, error) {
	var collected []watchRow
	cursor := ""
	for range maxPagesPerPoll {
		rows, next, err := fetchPage(ctx, cursor)
		if err != nil {
			return nil, err
		}
		collected = append(collected, rows...)
		// Rows are newest-first. If this page's oldest row is strictly older than
		// the watermark, all further pages are older too — stop.
		if !w.watermark.IsZero() && len(rows) > 0 {
			if oldest := rows[len(rows)-1].at; !oldest.IsZero() && oldest.Before(w.watermark) {
				break
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}

	// Keep only unseen rows, oldest-first for stable output.
	fresh := collected[:0:0]
	for _, r := range collected {
		if _, ok := w.seen[r.key]; ok {
			continue
		}
		fresh = append(fresh, r)
	}
	sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].at.Before(fresh[j].at) })

	for _, r := range fresh {
		w.markSeen(r.key)
		if r.at.After(w.watermark) {
			w.watermark = r.at
		}
	}
	return fresh, nil
}

// markSeen records key, evicting the oldest entry when the set is at capacity.
func (w *watcher) markSeen(key string) {
	if _, ok := w.seen[key]; ok {
		return
	}
	w.seen[key] = struct{}{}
	w.order = append(w.order, key)
	if len(w.order) > maxSeenKeys {
		oldest := w.order[0]
		w.order = w.order[1:]
		delete(w.seen, oldest)
	}
}

func watchTarget(id, repo string) string {
	if repo != "" {
		return "repo " + repo
	}
	return "sbom " + id
}

// watchRow is a de-duplicatable, printable event line. at is the parsed
// OccurredAt (zero if unparseable), used for watermarking and ordering.
type watchRow struct {
	key  string
	line string
	at   time.Time
}

// parseAt parses an RFC3339 timestamp, returning the zero time on failure so
// callers degrade to key-based dedup rather than crashing.
func parseAt(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return time.Time{}
}

func eventRows(events []client.Event) []watchRow {
	rows := make([]watchRow, 0, len(events))
	for _, e := range events {
		key := fmt.Sprintf("%s|%s|%s|%s", e.OccurredAt, e.EventType, e.Exposure, e.Package)
		line := fmt.Sprintf("%s  %-8s %-9s %s %s (%s)", e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, e.Cause)
		rows = append(rows, watchRow{key: key, line: line, at: parseAt(e.OccurredAt)})
	}
	return rows
}

func timelineRows(events []client.TimelineEvent) []watchRow {
	rows := make([]watchRow, 0, len(events))
	for _, e := range events {
		key := fmt.Sprintf("%s|%s|%s|%s|%s", e.OccurredAt, e.EventType, e.Exposure, e.Package, e.Digest)
		line := fmt.Sprintf("%s  %-8s %-9s %s %s [%s]", e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, shortDigest(e.Digest))
		rows = append(rows, watchRow{key: key, line: line, at: parseAt(e.OccurredAt)})
	}
	return rows
}
