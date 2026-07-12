package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thingzio/devradarctl/internal/client"
)

// jsonServer returns a server that writes body as a JSON response for any
// request. Close is the caller's responsibility.
func jsonServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestSBOMGet_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"sbom_id":"sb-1","format":"cyclonedx","status":"active","counts":{"critical":1,"total":3}}`)
	defer srv.Close()
	if err := runArgs(t, "sbom", "get", "sb-1", "--base-url", srv.URL); err != nil {
		t.Fatalf("sbom get: %v", err)
	}
}

func TestSBOMEvents_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"events":[{"event_type":"added","severity":"high","exposure":"CVE-1","package":"p","cause":"db","occurred_at":"2024-01-01T00:00:00Z"}]}`)
	defer srv.Close()
	if err := runArgs(t, "sbom", "events", "sb-1", "--base-url", srv.URL); err != nil {
		t.Fatalf("sbom events: %v", err)
	}
}

func TestSBOMFailures_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"failures":[{"scanner":"grype","stage":"scan","error":"boom","occurred_at":"2024-01-01T00:00:00Z"}]}`)
	defer srv.Close()
	if err := runArgs(t, "sbom", "failures", "sb-1", "--base-url", srv.URL); err != nil {
		t.Fatalf("sbom failures: %v", err)
	}
}

func TestSBOMLicenses_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"packages":[{"package":"p","version":"1","category":"strong-copyleft","licenses":["GPL-3.0"],"violation":true,"reason":"GPL-3.0 denied"}]}`)
	defer srv.Close()
	if err := runArgs(t, "sbom", "licenses", "sb-1", "--base-url", srv.URL); err != nil {
		t.Fatalf("sbom licenses: %v", err)
	}
}

func TestImagesList_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"images":[{"repository":"repo/a","sbom_count":2,"digest_count":1,"counts":{"total":5,"critical":1},"fixable":2,"failures":0,"latest_at":"2024-01-01T00:00:00Z"}]}`)
	defer srv.Close()
	if err := runArgs(t, "images", "list", "--base-url", srv.URL); err != nil {
		t.Fatalf("images list: %v", err)
	}
}

func TestImagesTimeline_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"repository":"repo/a","timeline":[{"event_type":"added","severity":"high","exposure":"CVE-1","package":"p","digest":"sha256:abcdef0123456789","cause":"image","occurred_at":"2024-01-01T00:00:00Z"}]}`)
	defer srv.Close()
	if err := runArgs(t, "images", "timeline", "--repo", "repo/a", "--base-url", srv.URL); err != nil {
		t.Fatalf("images timeline: %v", err)
	}
}

func TestLicensesFleet_Table(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"packages":10,"unlicensed":1,"violations":0,"categories":[{"key":"permissive","count":10}],"families":[{"key":"MIT","count":8}]}`)
	defer srv.Close()
	if err := runArgs(t, "licenses", "--base-url", srv.URL); err != nil {
		t.Fatalf("licenses: %v", err)
	}
}

func TestVEXList_JSON(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	srv := jsonServer(t, `{"documents":[{"@id":"vex-1"}]}`)
	defer srv.Close()
	if err := runArgs(t, "vex", "list", "--base-url", srv.URL, "-o", "json"); err != nil {
		t.Fatalf("vex list: %v", err)
	}
	// table path too
	if err := runArgs(t, "vex", "list", "--base-url", srv.URL); err != nil {
		t.Fatalf("vex list table: %v", err)
	}
}

func TestVEXSubmit_MissingFile(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	err := runArgs(t, "vex", "submit", "/no/such/file.json")
	if err == nil || !strings.Contains(err.Error(), "read VEX file") {
		t.Fatalf("want read error, got %v", err)
	}
}

func TestArchive_AbortsWithoutConfirm(t *testing.T) {
	t.Setenv("DEVRADAR_TOKEN", "tok")
	// No --yes and a non-interactive (nil) reader → confirm returns false → abort.
	err := runArgs(t, "sbom", "archive", "sb-1")
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("want abort, got %v", err)
	}
}

func TestSeveritySummary(t *testing.T) {
	got := severitySummary(client.SeverityCounts{Critical: 2, High: 1, Total: 5})
	if !strings.Contains(got, "crit=2") || !strings.Contains(got, "high=1") || !strings.Contains(got, "total=5") {
		t.Errorf("summary = %q", got)
	}
	if empty := severitySummary(client.SeverityCounts{Total: 0}); empty != "total=0" {
		t.Errorf("empty summary = %q, want total=0", empty)
	}
}

func TestGateBreach_MaxThresholds(t *testing.T) {
	findings := []client.Finding{{Severity: "high"}, {Severity: "high"}, {Severity: "medium"}}
	cmd := sbomFindingsCmd()
	// Build a parse state with --max-high 1 → breach (2 highs).
	if err := cmd.Set(flagMaxHigh, "1"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	if reason := gateBreach(cmd, findings); reason == "" {
		t.Error("expected breach for max-high 1 with 2 highs")
	}
}
