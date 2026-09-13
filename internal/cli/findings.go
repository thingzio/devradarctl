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

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
)

// exitBreach is the process exit code returned when --exit-code is set and a
// findings threshold is breached.
const exitBreach = 2

func runFindings(ctx context.Context, c *cli.Command) error {
	if err := validateFailOn(c); err != nil {
		return err
	}
	id, err := firstArg(c, "sbom-id")
	if err != nil {
		return err
	}
	cl, err := apiClient(c) // also fail-closes on invalid shared flags
	if err != nil {
		return err
	}

	all := c.Bool(flagAll)
	exitCode := c.Bool(flagExitCode)
	// JSON always returns the full set; a table shows one page unless --all.
	// A CI gate (--exit-code) must consider EVERY finding, so it forces full
	// paging regardless of --all — otherwise the gate could pass on page one
	// while a critical sits on page two.
	fetchAll := all || asJSON(c) || exitCode

	opts := client.FindingsOptions{
		ListOptions: listOptions(c),
		Fixable:     c.Bool(flagFixable),
		Suppressed:  c.Bool(flagSuppressed),
	}

	var findings []client.Finding
	var lastCursor string
	for {
		pg, err := cl.Findings(ctx, id, opts)
		if err != nil {
			return err
		}
		findings = append(findings, pg.Findings...)
		lastCursor = pg.NextCursor
		if pg.NextCursor == "" || !fetchAll {
			break
		}
		opts.Cursor = pg.NextCursor
	}

	if err := render(c, findings, func(w io.Writer) { findingTable(w, findings) }); err != nil {
		return err
	}
	moreHint(c, lastCursor, all)

	if exitCode {
		if reason := gateBreach(c, findings); reason != "" {
			fmt.Fprintf(c.ErrWriter, "gate failed: %s\n", reason)
			return cli.Exit("", exitBreach)
		}
	}
	return nil
}

// gateBreach returns a human reason when the findings breach a configured
// threshold, or "" when they pass. Thresholds are evaluated over the fetched
// findings, so callers gating in CI should pair --exit-code with --all (or JSON)
// to consider every page.
func gateBreach(c *cli.Command, findings []client.Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	if floor := c.String(flagFailOn); floor != "" {
		min, ok := severityRank[floor]
		if !ok {
			return fmt.Sprintf("unknown --fail-on severity %q", floor)
		}
		for sev, n := range counts {
			if n > 0 && severityRank[sev] >= min {
				return fmt.Sprintf("%d finding(s) at or above %s", countAtOrAbove(counts, min), floor)
			}
		}
	}

	for _, m := range []struct {
		flag, sev string
	}{
		{flagMaxCritical, sevCritical},
		{flagMaxHigh, sevHigh},
		{flagMaxMedium, sevMedium},
	} {
		if max := c.Int(m.flag); max >= 0 && counts[m.sev] > max {
			return fmt.Sprintf("%s findings %d exceed max %d", m.sev, counts[m.sev], max)
		}
	}
	return ""
}

// countAtOrAbove sums counts for severities at or above rank min.
func countAtOrAbove(counts map[string]int, min int) int {
	total := 0
	for sev, n := range counts {
		if severityRank[sev] >= min {
			total += n
		}
	}
	return total
}
