package cli

import (
	"github.com/urfave/cli/v3"

	"github.com/thingzio/devradarctl/internal/sbom"
)

// Flag names shared across commands, kept as constants so lookups can't drift
// from declarations.
const (
	flagImage       = "image"
	flagSyftPath    = "syft-path"
	flagScope       = "scope"
	flagFile        = "file"
	flagImageRef    = "image-ref"
	flagTag         = "tag"
	flagLabel       = "label"
	flagBaseURL     = "base-url"
	flagAttestation = "attestation"

	// flagOutput is the read commands' --output/-o format selector (table|json).
	flagOutput = "output"
	// flagOutFile is `sbom generate`'s --output/-o destination file path. It
	// shares the "output" name/alias with flagOutput but is disjoint (a
	// different command) and carries file, not format, semantics.
	flagOutFile = "output"

	// Read/query and list-paging flags.
	flagMinSeverity = "min-severity"
	flagFixable     = "fixable"
	flagSuppressed  = "suppressed"
	flagSort        = "sort"
	flagDir         = "dir"
	flagLimit       = "limit"
	flagAll         = "all"
	flagRepo        = "repo"

	// findings CI-gate flags.
	flagExitCode    = "exit-code"
	flagFailOn      = "fail-on"
	flagMaxCritical = "max-critical"
	flagMaxHigh     = "max-high"
	flagMaxMedium   = "max-medium"

	// watch flags.
	flagInterval = "interval"

	// archive confirmation.
	flagYes = "yes"

	// submit attestation enforcement.
	flagRequireVerified = "require-verified-attestation"
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
