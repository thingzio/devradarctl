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

// maxSBOMBytes bounds syft's stdout so a runaway/hostile generation cannot
// exhaust memory. It matches the DevRadar API's 20 MiB decoded-SBOM limit —
// a larger document would be rejected on submit anyway.
const maxSBOMBytes = 20 << 20

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

	// Bound stdout so an unexpectedly huge document can't exhaust memory; cap
	// stderr too since it is only used for an error message.
	stdout := &capBuffer{max: maxSBOMBytes}
	stderr := &capBuffer{max: 64 << 10}
	cmd := exec.CommandContext(ctx, opts.SyftPath, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("syft failed: %s", msg)
	}
	if stdout.overflow {
		return nil, fmt.Errorf("syft produced an SBOM larger than the %d-byte limit", maxSBOMBytes)
	}
	if stdout.Len() == 0 {
		return nil, errors.New("syft produced an empty SBOM")
	}
	return stdout.Bytes(), nil
}

// capBuffer is a bytes.Buffer that stops accepting data past max and records
// that truncation happened, so a caller can distinguish a bounded read from a
// complete one. Writes past the cap are discarded (not errored) so the child
// process's pipe never blocks.
type capBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if remaining := b.max - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.overflow = true
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.overflow = true
	}
	// Report the full length so the writer (os/exec copy) treats it as consumed.
	return len(p), nil
}

func (b *capBuffer) Len() int       { return b.buf.Len() }
func (b *capBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *capBuffer) String() string { return b.buf.String() }
