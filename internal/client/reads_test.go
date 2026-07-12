package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// containsParam reports whether haystack contains needle — used for
// order-independent query-param and error-body assertions.
func containsParam(haystack, needle string) bool { return strings.Contains(haystack, needle) }

// newTestServer returns a server that records the request path+query and auth
// header, and writes body as the response. Close is the caller's responsibility.
func newTestServer(t *testing.T, body string, gotPath, gotQuery, gotAuth, gotMethod *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.Path
		*gotQuery = r.URL.RawQuery
		*gotAuth = r.Header.Get("Authorization")
		*gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestGetSBOM(t *testing.T) {
	var path, query, auth, method string
	srv := newTestServer(t, `{"sbom_id":"sb-1","format":"cyclonedx","counts":{"critical":2,"total":10}}`,
		&path, &query, &auth, &method)
	defer srv.Close()

	got, err := New(srv.URL, "tok").GetSBOM(context.Background(), "sb-1", "high")
	if err != nil {
		t.Fatalf("GetSBOM: %v", err)
	}
	if path != "/v1/sboms/sb-1" {
		t.Errorf("path = %q", path)
	}
	if query != "min_severity=high" {
		t.Errorf("query = %q", query)
	}
	if auth != "Bearer tok" {
		t.Errorf("auth = %q", auth)
	}
	if got.SBOMID != "sb-1" || got.Counts.Critical != 2 || got.Counts.Total != 10 {
		t.Errorf("decoded = %+v", got)
	}
}

func TestFindings(t *testing.T) {
	var path, query, auth, method string
	srv := newTestServer(t, `{"next_cursor":"c2","findings":[{"exposure":"CVE-2024-1","severity":"high","score":7.5,"kev":true}]}`,
		&path, &query, &auth, &method)
	defer srv.Close()

	got, err := New(srv.URL, "tok").Findings(context.Background(), "sb-1", FindingsOptions{
		ListOptions: ListOptions{MinSeverity: "high", Limit: 50},
		Fixable:     true,
	})
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if path != "/v1/sboms/sb-1/findings" {
		t.Errorf("path = %q", path)
	}
	// Query param presence (order-independent).
	for _, want := range []string{"min_severity=high", "limit=50", "fixable=true"} {
		if !containsParam(query, want) {
			t.Errorf("query %q missing %q", query, want)
		}
	}
	if got.NextCursor != "c2" || len(got.Findings) != 1 || got.Findings[0].Exposure != "CVE-2024-1" || !got.Findings[0].KEV {
		t.Errorf("decoded = %+v", got)
	}
}

func TestArchiveSBOM(t *testing.T) {
	var method, path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := New(srv.URL, "tok").ArchiveSBOM(context.Background(), "sb-1"); err != nil {
		t.Fatalf("ArchiveSBOM: %v", err)
	}
	if method != http.MethodDelete || path != "/v1/sboms/sb-1" {
		t.Errorf("method/path = %s %s", method, path)
	}
}

func TestImages(t *testing.T) {
	var path, query, auth, method string
	srv := newTestServer(t, `{"images":[{"repository":"repo/a","sbom_count":3,"counts":{"total":5}}]}`,
		&path, &query, &auth, &method)
	defer srv.Close()

	got, err := New(srv.URL, "tok").Images(context.Background(), ImagesOptions{
		ListOptions: ListOptions{MinSeverity: "medium"},
		Query:       "repo",
		Label:       "prod",
	})
	if err != nil {
		t.Fatalf("Images: %v", err)
	}
	if path != "/v1/images" {
		t.Errorf("path = %q", path)
	}
	for _, want := range []string{"q=repo", "label=prod", "min_severity=medium"} {
		if !containsParam(query, want) {
			t.Errorf("query %q missing %q", query, want)
		}
	}
	if len(got.Images) != 1 || got.Images[0].Repository != "repo/a" || got.Images[0].SBOMCount != 3 {
		t.Errorf("decoded = %+v", got)
	}
}

func TestTimeline_RequiresRepoParam(t *testing.T) {
	var path, query, auth, method string
	srv := newTestServer(t, `{"repository":"repo/a","timeline":[]}`, &path, &query, &auth, &method)
	defer srv.Close()

	if _, err := New(srv.URL, "tok").Timeline(context.Background(), "repo/a", ListOptions{}); err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if path != "/v1/images/timeline" || !containsParam(query, "repo=repo%2Fa") {
		t.Errorf("path/query = %q %q", path, query)
	}
}

func TestFleetLicenses(t *testing.T) {
	var path, query, auth, method string
	srv := newTestServer(t, `{"packages":42,"unlicensed":3,"violations":1,"categories":[{"key":"permissive","count":40}]}`,
		&path, &query, &auth, &method)
	defer srv.Close()

	got, err := New(srv.URL, "tok").FleetLicenses(context.Background())
	if err != nil {
		t.Fatalf("FleetLicenses: %v", err)
	}
	if path != "/v1/licenses" {
		t.Errorf("path = %q", path)
	}
	if got.Packages != 42 || got.Violations != 1 || len(got.Categories) != 1 {
		t.Errorf("decoded = %+v", got)
	}
}

func TestSubmitVEX(t *testing.T) {
	var method, path string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"document_id":"doc-1","statements":3,"matched":2}`))
	}))
	defer srv.Close()

	doc := []byte(`{"@context":"https://openvex.dev/ns"}`)
	got, err := New(srv.URL, "tok").SubmitVEX(context.Background(), doc)
	if err != nil {
		t.Fatalf("SubmitVEX: %v", err)
	}
	if method != http.MethodPost || path != "/v1/vex" {
		t.Errorf("method/path = %s %s", method, path)
	}
	if string(body) != string(doc) {
		t.Errorf("body = %q, want raw doc", body)
	}
	if got.DocumentID != "doc-1" || got.Statements != 3 || got.Matched != 2 {
		t.Errorf("decoded = %+v", got)
	}
}

func TestSubmitVEX_RejectsInvalidJSON(t *testing.T) {
	if _, err := New("http://example.invalid", "tok").SubmitVEX(context.Background(), []byte("not json")); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestGet_ErrorStatusIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").GetSBOM(context.Background(), "missing", "")
	if err == nil {
		t.Fatal("expected error on 404")
	}
	if !containsParam(err.Error(), "not found") {
		t.Errorf("error should include body: %v", err)
	}
}
