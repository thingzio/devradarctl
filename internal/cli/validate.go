package cli

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"
)

// validSeverities is the set the API accepts for min_severity / fail-on floors.
var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "negligible": true,
}

// maxLimit mirrors the API's documented per-page ceiling.
const maxLimit = 1000

// validateCommon fail-closes on invalid shared flags before any network call,
// so a typo degrades to a clear error rather than silently wrong behavior
// (e.g. an unknown --output falling through to a table, or an out-of-range
// --limit the server rejects opaquely).
func validateCommon(c *cli.Command) error {
	if out := c.String(flagOutput); out != outputTable && out != outputJSON {
		return fmt.Errorf("invalid --output %q: want %s or %s", out, outputTable, outputJSON)
	}
	if sev := c.String(flagMinSeverity); sev != "" && !validSeverities[sev] {
		return fmt.Errorf("invalid --min-severity %q: want one of critical|high|medium|low|negligible", sev)
	}
	if dir := c.String(flagDir); dir != "" && dir != "asc" && dir != "desc" {
		return fmt.Errorf("invalid --dir %q: want asc or desc", dir)
	}
	// c.Int is only meaningful when the flag exists on the command; IsSet guards
	// commands (e.g. get) that don't define --limit.
	if c.IsSet(flagLimit) {
		if lim := c.Int(flagLimit); lim < 1 || lim > maxLimit {
			return fmt.Errorf("invalid --limit %d: want 1..%d", lim, maxLimit)
		}
	}
	return nil
}

// validateFailOn checks the --fail-on floor names a known severity. Empty is
// allowed (no floor configured).
func validateFailOn(c *cli.Command) error {
	if floor := c.String(flagFailOn); floor != "" && !validSeverities[strings.ToLower(floor)] {
		return fmt.Errorf("invalid --fail-on %q: want one of critical|high|medium|low|negligible", floor)
	}
	return nil
}
