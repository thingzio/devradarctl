package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/thingzio/devradarctl/internal/client"
)

// severitySummary renders a compact one-line severity breakdown, omitting
// zero buckets. Falls back to the total when every bucket is zero.
func severitySummary(c client.SeverityCounts) string {
	parts := make([]string, 0, 6)
	for _, b := range []struct {
		label string
		n     int
	}{
		{"crit", c.Critical}, {"high", c.High}, {"med", c.Medium},
		{"low", c.Low}, {"negl", c.Negligible}, {"unknown", c.Unknown},
	} {
		if b.n > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", b.label, b.n))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("total=%d", c.Total)
	}
	return fmt.Sprintf("%s (total=%d)", strings.Join(parts, " "), c.Total)
}

// findingTable writes findings as a severity-ranked table.
func findingTable(w io.Writer, findings []client.Finding) {
	fmt.Fprintln(w, "SEVERITY\tCVE\tPACKAGE\tVERSION\tSCORE\tFIX\tEPSS\tKEV")
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Severity, f.Exposure, f.Package, f.Version,
			score(f.Score), yesNo(f.IsFixed), pct(f.EPSS), flag(f.KEV))
	}
}

// eventTable writes change-log events as a table.
func eventTable(w io.Writer, events []client.Event) {
	fmt.Fprintln(w, "OCCURRED\tTYPE\tSEVERITY\tCVE\tPACKAGE\tCAUSE\tSCANNER")
	for _, e := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, e.Cause, e.Scanner)
	}
}

// timelineTable writes timeline events (event plus digest) as a table.
func timelineTable(w io.Writer, events []client.TimelineEvent) {
	fmt.Fprintln(w, "OCCURRED\tTYPE\tSEVERITY\tCVE\tPACKAGE\tDIGEST\tCAUSE")
	for _, e := range events {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.OccurredAt, e.EventType, e.Severity, e.Exposure, e.Package, shortDigest(e.Digest), e.Cause)
	}
}

func joinList(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ", ")
}

func score(f float64) string {
	if f == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f", f)
}

func pct(f float64) string {
	if f == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func flag(b bool) string {
	if b {
		return "KEV"
	}
	return "-"
}

// shortDigest trims a sha256:... digest to a readable prefix.
func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// confirm prompts on w and reads a yes/no answer from r, returning true only on
// an explicit yes. A non-interactive (nil/EOF) reader yields false so
// destructive actions are never auto-approved.
func confirm(r io.Reader, w io.Writer, prompt string) bool {
	if r == nil {
		return false
	}
	fmt.Fprint(w, prompt)
	line, _ := bufio.NewReader(r).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
