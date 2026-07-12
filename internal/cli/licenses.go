package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"
)

// licensesCmd is the top-level fleet-wide license rollup. Per-SBOM license
// detail lives under `sbom licenses <id>`.
func licensesCmd() *cli.Command {
	return &cli.Command{
		Name:  "licenses",
		Usage: "Show the fleet-wide license rollup",
		Flags: []cli.Flag{baseURLFlag(), outputFlag()},
		Action: func(ctx context.Context, c *cli.Command) error {
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			stats, err := cl.FleetLicenses(ctx)
			if err != nil {
				return err
			}
			return render(c, stats, func(w io.Writer) {
				fmt.Fprintf(w, "Packages\t%d\n", stats.Packages)
				fmt.Fprintf(w, "Unlicensed\t%d\n", stats.Unlicensed)
				fmt.Fprintf(w, "Violations\t%d\n", stats.Violations)
				fmt.Fprintln(w, "\nCATEGORY\tCOUNT")
				for _, cat := range stats.Categories {
					fmt.Fprintf(w, "%s\t%d\n", cat.Key, cat.Count)
				}
				fmt.Fprintln(w, "\nFAMILY\tCOUNT")
				for _, fam := range stats.Families {
					fmt.Fprintf(w, "%s\t%d\n", fam.Key, fam.Count)
				}
			})
		},
	}
}
