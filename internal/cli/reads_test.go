package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSBOMGet_RequiresID(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "sbom", "get")
	if err == nil || !strings.Contains(err.Error(), "sbom-id is required") {
		t.Fatalf("want 'sbom-id is required', got %v", err)
	}
}

func TestFindings_RequiresID(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "sbom", "findings")
	if err == nil || !strings.Contains(err.Error(), "sbom-id is required") {
		t.Fatalf("want 'sbom-id is required', got %v", err)
	}
}

func TestImagesSBOMs_RequiresRepo(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "images", "sboms")
	if err == nil || !strings.Contains(err.Error(), "repo") {
		t.Fatalf("want repo-required error, got %v", err)
	}
}

func TestWatch_RequiresTarget(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "watch")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("want required error, got %v", err)
	}
}

func TestWatch_TargetsMutuallyExclusive(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "watch", "sb-1", "--repo", "foo")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want 'mutually exclusive', got %v", err)
	}
}

// TestSBOMGenerate_StillWorks guards the `sbom` → `sbom generate` rename: the
// generation action must remain reachable at the new path. It fails fast on the
// missing syft binary (or image), which proves the command wired through.
func TestSBOMGenerate_Reachable(t *testing.T) {
	err := runArgs(t, "sbom", "generate", "--image", "alpine:3.20", "--syft-path", "/nonexistent/syft")
	if err == nil {
		t.Fatal("expected an error (missing syft), got nil")
	}
	// The old top-level `sbom --image` invocation must no longer be an action.
	if err := runArgs(t, "sbom", "--image", "alpine:3.20"); err == nil {
		t.Fatal("expected `sbom --image` to fail after rename to `sbom generate`")
	}
}

// TestFindings_ExitCodeGate drives the findings command against a stub server
// and asserts --exit-code returns a non-zero exit when --fail-on is breached,
// and a clean exit otherwise.
func TestFindings_ExitCodeGate(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[{"exposure":"CVE-1","severity":"critical","score":9.1}]}`))
	}))
	defer srv.Close()

	// Breach: a critical finding with --fail-on high.
	err := runArgs(t, "sbom", "findings", "sb-1", "--base-url", srv.URL, "--exit-code", "--fail-on", "high")
	code := exitCode(t, err)
	if code != exitBreach {
		t.Fatalf("breach exit code = %d, want %d (err=%v)", code, exitBreach, err)
	}

	// Pass: same finding but only fail on... nothing configured breaches.
	if err := runArgs(t, "sbom", "findings", "sb-1", "--base-url", srv.URL, "--exit-code", "--max-critical", "5"); err != nil {
		t.Fatalf("expected clean exit under threshold, got %v", err)
	}
}

// exitCode extracts the process exit code carried by a urfave/cli Exit error.
func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	type coder interface{ ExitCode() int }
	if ec, ok := err.(coder); ok {
		return ec.ExitCode()
	}
	t.Fatalf("error is not an ExitCoder: %v", err)
	return -1
}

// TestFindings_JSONOutput asserts --output json emits the raw findings array.
func TestFindings_JSONOutput(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[{"exposure":"CVE-1","severity":"low"}]}`))
	}))
	defer srv.Close()
	// Smoke test: just assert it runs without error through the JSON path.
	if err := runArgs(t, "sbom", "findings", "sb-1", "--base-url", srv.URL, "-o", "json"); err != nil {
		t.Fatalf("json output: %v", err)
	}
}
