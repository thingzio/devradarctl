package client

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// devradarSpecEnv optionally points at devradar's checkout so CI can pin the
// authoritative spec location. When unset, a few sibling-relative paths are
// tried; if none resolve, the test skips (the vendored copy is all we have).
const devradarSpecEnv = "DEVRADAR_OPENAPI"

// TestOpenAPISpec_IsCurrent guards against the vendored testdata/openapi.yaml
// drifting from devradar's source of truth. It compares byte-for-byte when the
// source spec is reachable, and skips otherwise so the suite still runs in
// isolation (e.g. release CI without the sibling repo checked out).
func TestOpenAPISpec_IsCurrent(t *testing.T) {
	src := locateDevradarSpec()
	if src == "" {
		t.Skip("devradar openapi.yaml not found; set " + devradarSpecEnv + " to enforce spec sync")
	}

	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read source spec %s: %v", src, err)
	}
	got, err := os.ReadFile("testdata/openapi.yaml")
	if err != nil {
		t.Fatalf("read vendored spec: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("testdata/openapi.yaml is stale vs %s\n"+
			"refresh it: cp %s internal/client/testdata/openapi.yaml", src, src)
	}
}

// locateDevradarSpec returns the path to devradar's openapi.yaml, or "" if it
// can't be found.
func locateDevradarSpec() string {
	if p := os.Getenv(devradarSpecEnv); p != "" {
		if fileExists(p) {
			return p
		}
		return ""
	}
	// Common layout: devradar checked out beside devradarctl.
	const rel = "pkg/server/static/openapi.yaml"
	for _, base := range []string{
		filepath.Join("..", "..", "..", "devradar"),
		filepath.Join("..", "..", "..", "..", "devradar"),
	} {
		if p := filepath.Join(base, rel); fileExists(p) {
			return p
		}
	}
	return ""
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
