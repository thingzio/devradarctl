package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/urfave/cli/v3"
)

// Output formats.
const (
	outputTable = "table"
	outputJSON  = "json"
)

// outputFlag returns a fresh --output/-o flag for read commands (table default,
// or json for machine consumption). Returned per call so urfave/cli's parsed
// state never leaks between commands.
func outputFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    flagOutput,
		Aliases: []string{"o"},
		Usage:   "output format: table|json",
		Value:   outputTable,
		Sources: cli.EnvVars("DEVRADAR_OUTPUT"),
	}
}

// asJSON reports whether the command's --output selects JSON.
func asJSON(c *cli.Command) bool { return c.String(flagOutput) == outputJSON }

// render writes data to the command's stdout in the selected format. For json
// it emits an indented document; for table it runs the provided closure over a
// tabwriter. Routing through c.Writer (not os.Stdout) keeps output testable.
func render(c *cli.Command, data any, table func(w io.Writer)) error {
	if asJSON(c) {
		return writeJSON(c.Writer, data)
	}
	tw := tabwriter.NewWriter(c.Writer, 0, 4, 2, ' ', 0)
	table(tw)
	return tw.Flush()
}

// writeJSON emits data as an indented JSON document with a trailing newline.
func writeJSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

// moreHint prints the "more available" nudge shown after a truncated table when
// another page exists and --all was not requested. It is intentionally silent
// for JSON callers (they receive the full set). Written to the command's
// stderr so it never contaminates piped stdout.
func moreHint(c *cli.Command, nextCursor string, all bool) {
	if nextCursor != "" && !all {
		fmt.Fprintln(c.ErrWriter, "more results available; pass --all to fetch every page")
	}
}
