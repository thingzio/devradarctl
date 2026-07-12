package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/client"
)

// imagesCmd is the `images` group: the tracked-image fleet view and per-image
// history.
func imagesCmd() *cli.Command {
	return &cli.Command{
		Name:            "images",
		Usage:           "List tracked images and their history",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			imagesListCmd(),
			imagesTimelineCmd(),
			imagesSBOMsCmd(),
		},
	}
}

func imagesListCmd() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List tracked images, grouped by repository and risk-ranked",
		Flags: append(listFlags(),
			baseURLFlag(), outputFlag(),
			&cli.StringFlag{Name: "q", Usage: "filter by repository name substring"},
			&cli.StringFlag{Name: "label", Usage: "filter to images carrying this label"},
		),
		Action: func(ctx context.Context, c *cli.Command) error {
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			all := c.Bool(flagAll)
			fetchAll := all || asJSON(c)
			opts := client.ImagesOptions{
				ListOptions: listOptions(c),
				Query:       c.String("q"),
				Label:       c.String("label"),
			}
			var images []client.RepoImage
			var lastCursor string
			for {
				pg, err := cl.Images(ctx, opts)
				if err != nil {
					return err
				}
				images = append(images, pg.Images...)
				lastCursor = pg.NextCursor
				if pg.NextCursor == "" || !fetchAll {
					break
				}
				opts.Cursor = pg.NextCursor
			}
			if err := render(c, images, func(w io.Writer) {
				fmt.Fprintln(w, "REPOSITORY\tSBOMS\tDIGESTS\tSEVERITY\tFIXABLE\tFAILURES\tLATEST")
				for _, im := range images {
					fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%d\t%d\t%s\n",
						im.Repository, im.SBOMCount, im.DigestCount,
						severitySummary(im.Counts), im.Fixable, im.Failures, im.LatestAt)
				}
			}); err != nil {
				return err
			}
			moreHint(lastCursor, all)
			return nil
		},
	}
}

func imagesTimelineCmd() *cli.Command {
	return &cli.Command{
		Name:  "timeline",
		Usage: "Show an image's change history across all digests",
		Flags: append(listFlags(),
			baseURLFlag(), outputFlag(),
			&cli.StringFlag{Name: flagRepo, Required: true, Usage: "repository (registry/path)"},
		),
		Action: func(ctx context.Context, c *cli.Command) error {
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			all := c.Bool(flagAll)
			fetchAll := all || asJSON(c)
			opts := listOptions(c)
			var events []client.TimelineEvent
			var lastCursor string
			for {
				pg, err := cl.Timeline(ctx, c.String(flagRepo), opts)
				if err != nil {
					return err
				}
				events = append(events, pg.Timeline...)
				lastCursor = pg.NextCursor
				if pg.NextCursor == "" || !fetchAll {
					break
				}
				opts.Cursor = pg.NextCursor
			}
			if err := render(c, events, func(w io.Writer) { timelineTable(w, events) }); err != nil {
				return err
			}
			moreHint(lastCursor, all)
			return nil
		},
	}
}

func imagesSBOMsCmd() *cli.Command {
	return &cli.Command{
		Name:  "sboms",
		Usage: "List the submitted SBOMs for one image",
		Flags: append(listFlags(),
			baseURLFlag(), outputFlag(),
			&cli.StringFlag{Name: flagRepo, Required: true, Usage: "repository (registry/path)"},
		),
		Action: func(ctx context.Context, c *cli.Command) error {
			cl, err := apiClient(c)
			if err != nil {
				return err
			}
			all := c.Bool(flagAll)
			fetchAll := all || asJSON(c)
			opts := listOptions(c)
			var sboms []client.Image
			var lastCursor string
			for {
				pg, err := cl.ImageSBOMs(ctx, c.String(flagRepo), opts)
				if err != nil {
					return err
				}
				sboms = append(sboms, pg.SBOMs...)
				lastCursor = pg.NextCursor
				if pg.NextCursor == "" || !fetchAll {
					break
				}
				opts.Cursor = pg.NextCursor
			}
			if err := render(c, sboms, func(w io.Writer) {
				fmt.Fprintln(w, "SBOM\tIMAGE\tFORMAT\tSEVERITY\tFAILURES\tSUBMITTED")
				for _, s := range sboms {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
						s.SBOMID, s.ImageRef, s.Format, severitySummary(s.Counts), s.Failures, s.SubmittedAt)
				}
			}); err != nil {
				return err
			}
			moreHint(lastCursor, all)
			return nil
		},
	}
}
