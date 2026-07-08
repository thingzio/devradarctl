package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// DefaultSyftPath is the syft binary looked up on PATH when none is configured.
const DefaultSyftPath = "syft"

// DefaultScope is the syft cataloging scope. "all-layers" walks every image
// layer (not just the squashed filesystem), which surfaces packages that a
// later layer deletes or shadows — the safest default for inventory.
const DefaultScope = "all-layers"

// Options controls SBOM generation.
type Options struct {
	// SyftPath is the syft binary to invoke (name on PATH or absolute path).
	SyftPath string
	// Scope is the syft cataloging scope (e.g. "all-layers", "squashed").
	Scope string
}

// withDefaults returns o with empty fields replaced by package defaults.
func (o Options) withDefaults() Options {
	if o.SyftPath == "" {
		o.SyftPath = DefaultSyftPath
	}
	if o.Scope == "" {
		o.Scope = DefaultScope
	}
	return o
}

// EnsureSyft verifies the configured syft binary is resolvable, returning an
// actionable error if it is not. Callers should invoke this before generation
// so a missing dependency fails fast with clear guidance.
func EnsureSyft(syftPath string) error {
	if syftPath == "" {
		syftPath = DefaultSyftPath
	}
	if _, err := exec.LookPath(syftPath); err != nil {
		return fmt.Errorf("syft not found (looked for %q): install it from "+
			"https://github.com/anchore/syft, or pass --syft-path: %w", syftPath, err)
	}
	return nil
}

// Generate produces an all-layers CycloneDX-JSON SBOM for ref using syft. ref
// should be a digest-pinned reference (see PinnedRef) so the SBOM embeds the
// manifest digest. It returns the raw SBOM bytes.
func Generate(ctx context.Context, ref string, opts Options) ([]byte, error) {
	opts = opts.withDefaults()
	if err := EnsureSyft(opts.SyftPath); err != nil {
		return nil, err
	}

	args := []string{"-q", "--scope", opts.Scope, "-o", "cyclonedx-json", ref}
	slog.Debug("generating SBOM", "syft", opts.SyftPath, "args", args)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, opts.SyftPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("syft failed: %s", msg)
	}
	if stdout.Len() == 0 {
		return nil, errors.New("syft produced an empty SBOM")
	}
	return stdout.Bytes(), nil
}
