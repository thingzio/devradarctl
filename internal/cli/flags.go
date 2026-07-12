package cli

import (
	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/sbom"
)

// Flag names shared across commands, kept as constants so lookups can't drift
// from declarations.
const (
	flagImage       = "image"
	flagOutput      = "output"
	flagSyftPath    = "syft-path"
	flagScope       = "scope"
	flagFile        = "file"
	flagImageRef    = "image-ref"
	flagTag         = "tag"
	flagLabel       = "label"
	flagBaseURL     = "base-url"
	flagAttestation = "attestation"
)

// syftFlags returns the generation-tuning flags shared by `sbom` and the
// image mode of `submit`. Returned fresh per call so urfave/cli's per-run
// parsed state never leaks between commands.
func syftFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    flagSyftPath,
			Usage:   "path to the syft binary",
			Value:   sbom.DefaultSyftPath,
			Sources: cli.EnvVars("DEVRADAR_SYFT_PATH"),
		},
		&cli.StringFlag{
			Name:  flagScope,
			Usage: "syft cataloging scope (e.g. all-layers, squashed)",
			Value: sbom.DefaultScope,
		},
	}
}
