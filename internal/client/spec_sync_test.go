package client

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// liveSpecURL is the public, unauthenticated OpenAPI document served by the
// DevRadar service — the authoritative deployed contract. Overridable so a
// staging instance can be checked instead.
var liveSpecURL = func() string {
	if u := os.Getenv("DEVRADAR_OPENAPI_URL"); u != "" {
		return u
	}
	return "https://devradar.thingz.io/openapi.yaml"
}()

// TestOpenAPISpec_IsCurrent guards against the vendored testdata/openapi.yaml
// drifting from the live DevRadar contract. It fetches the public spec and
// compares, ignoring the info.version line (a per-deploy build stamp, not part
// of the request/response contract).
//
// Network-dependent, so it is skipped under `go test -short` and when the
// service is unreachable — the vendored copy still drives the offline contract
// test. CI runs it (not short) to catch drift straight from the published spec.
func TestOpenAPISpec_IsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network spec-sync check in -short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, liveSpecURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("live spec %s unreachable (%v); relying on vendored copy", liveSpecURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("live spec %s returned HTTP %d; relying on vendored copy", liveSpecURL, resp.StatusCode)
	}
	live, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read live spec: %v", err)
	}

	vendored, err := os.ReadFile("testdata/openapi.yaml")
	if err != nil {
		t.Fatalf("read vendored spec: %v", err)
	}

	if normalizeSpec(string(live)) != normalizeSpec(string(vendored)) {
		t.Fatalf("testdata/openapi.yaml is stale vs %s\n"+
			"refresh it: curl -sS %s -o internal/client/testdata/openapi.yaml",
			liveSpecURL, liveSpecURL)
	}
}

// normalizeSpec drops the top-level info.version line so a per-deploy version
// stamp does not trip the drift check — only the request/response contract
// matters here. The match is deliberately narrow (2-space indent, scalar value)
// so it can't remove the `version` schema properties nested deeper in the spec.
func normalizeSpec(s string) string {
	lines := strings.Split(s, "\n")
	out := lines[:0]
	for _, ln := range lines {
		if isInfoVersionLine(ln) {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// isInfoVersionLine reports whether ln is the top-level `info.version:` entry:
// exactly two leading spaces, then `version:` with a plain scalar value (not a
// nested schema like `version: { type: string }`).
func isInfoVersionLine(ln string) bool {
	const prefix = "  version:" // exactly two leading spaces
	if !strings.HasPrefix(ln, prefix) {
		return false
	}
	// Reject deeper indentation (e.g. a nested schema property): the character
	// right after the two spaces must be the 'v' of "version".
	if ln[2] != 'v' {
		return false
	}
	value := strings.TrimSpace(strings.TrimPrefix(ln, prefix))
	return value != "" && !strings.HasPrefix(value, "{")
}
