package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/sbom"
)

// sbomCmd is the `sbom` group: local generation plus the per-SBOM read
// operations against the DevRadar API.
func sbomCmd() *cli.Command {
	return &cli.Command{
		Name:            "sbom",
		Usage:           "Generate SBOMs and inspect them in DevRadar",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			sbomGenerateCmd(),
			sbomGetCmd(),
			sbomFindingsCmd(),
			sbomEventsCmd(),
			sbomFailuresCmd(),
			sbomLicensesCmd(),
			sbomArchiveCmd(),
		},
	}
}

// sbomGenerateCmd is the local syft generation action (formerly `sbom`). Here
// --output/-o is a destination file path, not a format selector.
func sbomGenerateCmd() *cli.Command {
	return &cli.Command{
		Name:      "generate",
		Usage:     "Generate an all-layers CycloneDX SBOM for a container image",
		ArgsUsage: " ",
		Description: "Resolves the image's manifest digest, then runs syft against the\n" +
			"digest-pinned reference to produce an all-layers CycloneDX-JSON SBOM.\n" +
			"syft must be on PATH (or pass --syft-path). Writes to stdout by default.",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:     flagImage,
				Aliases:  []string{"i"},
				Usage:    "container image reference (e.g. alpine:3.20 or repo@sha256:…)",
				Required: true,
			},
			&cli.StringFlag{
				Name:    flagOutFile,
				Aliases: []string{"o"},
				Usage:   "output file path (default: stdout)",
			},
		}, syftFlags()...),
		Action: func(ctx context.Context, c *cli.Command) error {
			res, err := generateSBOM(ctx, c.String(flagImage), sbom.Options{
				SyftPath: c.String(flagSyftPath),
				Scope:    c.String(flagScope),
			})
			if err != nil {
				return err
			}
			return writeOutput(c.String(flagOutFile), res.Doc)
		},
	}
}

// generateSBOM pins image to its digest and generates the SBOM, returning the
// raw bytes plus the digest-pinned reference so callers can reuse both. It does
// not write output — that is the caller's decision (the `sbom` command writes
// to a file or stdout; `submit` transmits without printing).
func generateSBOM(ctx context.Context, image string, opts sbom.Options) (result sbomResult, err error) {
	if err := sbom.EnsureSyft(opts.SyftPath); err != nil {
		return result, err
	}

	ref, err := sbom.PinnedRef(ctx, image)
	if err != nil {
		return result, err
	}
	slog.Debug("resolved image", "image", image, "ref", ref)

	doc, err := sbom.Generate(ctx, ref, opts)
	if err != nil {
		return result, fmt.Errorf("generate SBOM for %s: %w", ref, err)
	}
	return sbomResult{Ref: ref, Doc: doc}, nil
}

// sbomResult carries a generated SBOM and the digest-pinned reference it was
// generated against.
type sbomResult struct {
	Ref string
	Doc []byte
}

// writeOutput writes b to path, or to stdout when path is empty.
func writeOutput(path string, b []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	slog.Debug("wrote SBOM", "path", path, "bytes", len(b))
	return nil
}
