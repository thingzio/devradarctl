package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

// render writes data to stdout in the selected format. For json it emits an
// indented document; for table it runs the provided closure over a tabwriter
// flushed to stdout. Any format other than json is treated as table.
func render(c *cli.Command, data any, table func(w io.Writer)) error {
	if asJSON(c) {
		return writeJSON(os.Stdout, data)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
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
// for JSON callers (they receive the full set).
func moreHint(nextCursor string, all bool) {
	if nextCursor != "" && !all {
		fmt.Fprintln(os.Stderr, "more results available; pass --all to fetch every page")
	}
}
