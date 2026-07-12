package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

// vexCmd is the `vex` group: submit OpenVEX documents and list submitted ones.
func vexCmd() *cli.Command {
	return &cli.Command{
		Name:            "vex",
		Usage:           "Submit and list OpenVEX documents",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			vexSubmitCmd(),
			vexListCmd(),
		},
	}
}

func vexSubmitCmd() *cli.Command {
	return &cli.Command{
		Name:      "submit",
		Usage:     "Submit an OpenVEX document",
		ArgsUsage: "<file>",
		Flags:     []cli.Flag{baseURLFlag(), outputFlag()},
		Action: func(ctx context.Context, c *cli.Command) error {
			path, err := firstArg(c, "file")
			if err != nil {
				return err
			}
			doc, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read VEX file: %w", err)
			}
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			res, err := cl.SubmitVEX(ctx, doc)
			if err != nil {
				return err
			}
			return render(c, res, func(w io.Writer) {
				fmt.Fprintf(w, "Document\t%s\n", res.DocumentID)
				fmt.Fprintf(w, "Statements\t%d\n", res.Statements)
				fmt.Fprintf(w, "Matched\t%d\n", res.Matched)
				fmt.Fprintf(w, "Unmatched\t%d\n", res.Unmatched)
				fmt.Fprintf(w, "Skipped\t%d\n", res.Skipped)
				if res.Note != "" {
					fmt.Fprintf(w, "Note\t%s\n", res.Note)
				}
			})
		},
	}
}

func vexListCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List submitted OpenVEX documents (metadata only)",
		Flags: []cli.Flag{baseURLFlag(), outputFlag()},
		Action: func(ctx context.Context, c *cli.Command) error {
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			docs, err := cl.ListVEX(ctx)
			if err != nil {
				return err
			}
			// VEX documents are free-form; JSON is the faithful view. The table
			// lists a stable id/context summary when present.
			return render(c, docs, func(w io.Writer) {
				fmt.Fprintln(w, "INDEX\tSUMMARY")
				for i, d := range docs {
					fmt.Fprintf(w, "%d\t%s\n", i, vexSummary(d))
				}
			})
		},
	}
}

// vexSummary renders a best-effort one-line description of a free-form VEX
// document, preferring common OpenVEX identity fields.
func vexSummary(d map[string]any) string {
	for _, k := range []string{"@id", "id", "author", "@context"} {
		if v, ok := d[k]; ok {
			return fmt.Sprintf("%s=%v", k, v)
		}
	}
	return fmt.Sprintf("%d field(s)", len(d))
}
