package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thingzio/devradarctl/internal/client"
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

// attestStubServer returns a submit server that reports the given
// verification_status, so the attestation gate can be exercised offline.
func attestStubServer(t *testing.T, status string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sbom_id": "sb-1", "format": "cyclonedx", "verification_status": status,
		})
	}))
}

func TestSubmit_RequireVerifiedNeedsAttestation(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	sbomFile := writeTemp(t, "sbom.json", `{"bomFormat":"CycloneDX"}`)
	err := runArgs(t, "submit", "--file", sbomFile, "--require-verified-attestation")
	if err == nil || !strings.Contains(err.Error(), "needs --attestation") {
		t.Fatalf("want 'needs --attestation', got %v", err)
	}
}

func TestSubmit_AttestationGateFails(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := attestStubServer(t, "failed")
	defer srv.Close()
	sbomFile := writeTemp(t, "sbom.json", `{"bomFormat":"CycloneDX"}`)
	attFile := writeTemp(t, "att.json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)

	err := runArgs(t, "submit", "--file", sbomFile, "--attestation", attFile,
		"--require-verified-attestation", "--base-url", srv.URL)
	if code := exitCode(t, err); code != exitBreach {
		t.Fatalf("gate exit code = %d, want %d (err=%v)", code, exitBreach, err)
	}
}

func TestSubmit_AttestationGatePasses(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := attestStubServer(t, "verified")
	defer srv.Close()
	sbomFile := writeTemp(t, "sbom.json", `{"bomFormat":"CycloneDX"}`)
	attFile := writeTemp(t, "att.json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)

	if err := runArgs(t, "submit", "--file", sbomFile, "--attestation", attFile,
		"--require-verified-attestation", "--base-url", srv.URL); err != nil {
		t.Fatalf("verified gate should pass, got %v", err)
	}
}

func TestSubmitError_429AddsHint(t *testing.T) {
	err := submitError(&client.APIError{StatusCode: 429, Message: "tenant SBOM limit reached"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "tenant SBOM limit reached") {
		t.Errorf("lost original message: %q", msg)
	}
	if !strings.Contains(msg, "archive") || !strings.Contains(msg, "raise the limit") {
		t.Errorf("missing 429 hint: %q", msg)
	}
}

func TestSubmitError_PassesThroughNon429(t *testing.T) {
	orig := &client.APIError{StatusCode: 401, Message: "bad token"}
	got := submitError(orig)
	if got.Error() != orig.Error() {
		t.Errorf("non-429 should pass through unchanged, got %q", got.Error())
	}
	if strings.Contains(got.Error(), "hint:") {
		t.Errorf("non-429 should not get a hint: %q", got.Error())
	}
}

func TestResolveToken_Env(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "  env-tok  ")
	got, err := resolveToken(strings.NewReader(""))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "env-tok" {
		t.Errorf("token = %q, want env-tok (trimmed)", got)
	}
}

func TestResolveToken_Stdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	got, err := resolveToken(strings.NewReader("piped-tok\n"))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "piped-tok" {
		t.Errorf("token = %q, want piped-tok", got)
	}
}

func TestResolveToken_EnvBeatsStdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "env-tok")
	got, err := resolveToken(strings.NewReader("piped-tok"))
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "env-tok" {
		t.Errorf("token = %q, want env to win", got)
	}
}

func TestResolveToken_Missing(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	// A nil reader stands in for a TTY (no piped data).
	if _, err := resolveToken(nil); err == nil {
		t.Fatal("expected error when no token and no stdin, got nil")
	}
}

func TestResolveToken_EmptyStdin(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "")
	if _, err := resolveToken(strings.NewReader("   \n")); err == nil {
		t.Fatal("expected error on whitespace-only stdin, got nil")
	}
}
