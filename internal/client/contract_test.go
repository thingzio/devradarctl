package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/errors"
)

// TestSubmit_ConformsToOpenAPI validates that the request Client.Submit builds,
// and the response it accepts, conform to the DevRadar OpenAPI contract. The
// spec in testdata is a copy of the service's published OpenAPI document —
// refresh it when the API changes (see TestOpenAPISpec_IsCurrent).
//
// Scope: this catches wrong types, missing required fields, malformed values
// (e.g. a bad digest), bad enums, and path/method/auth mistakes. It does NOT
// catch sending a correctly-typed but wrongly-named optional field (the spec's
// SubmitRequest allows additional properties), so the exact wire field names
// are asserted separately in TestSubmit_Success.
func TestSubmit_ConformsToOpenAPI(t *testing.T) {
	spec, err := os.ReadFile("testdata/openapi.yaml")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	doc, err := libopenapi.NewDocument(spec)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		t.Fatalf("build validator: %v", errs)
	}
	if ok, verrs := v.ValidateDocument(); !ok {
		t.Fatalf("spec itself is invalid: %v", verrs)
	}

	// Capture the exact *http.Request Submit builds, then rebuild an equivalent
	// request (with the server's real path) to validate against the spec. The
	// httptest server URL uses a random port, so the captured request's path is
	// what matters, not its host.
	var captured *http.Request
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = b
		captured = r.Clone(context.Background())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202, per the OpenAPI spec
		_, _ = w.Write([]byte(`{"sbom_id":"sb-1","image_ref":"alpine@sha256:` + zeros64 +
			`","digest":"sha256:` + zeros64 + `","format":"cyclonedx","existing":false}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "dr_testtoken")
	if _, err := c.Submit(context.Background(), SubmitRequest{
		SBOM:     []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`),
		ImageRef: "alpine@sha256:" + zeros64,
		Version:  "3.20",
		Labels:   []string{"team-x", "prod"},
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if captured == nil {
		t.Fatal("server never received a request")
	}

	// Rebuild a request the validator can match to the spec path. Absolute URL
	// with the documented server path; carry over method, headers, and body.
	req, err := http.NewRequest(captured.Method, "https://devradar.thingz.io"+captured.URL.Path, bytes.NewReader(capturedBody))
	if err != nil {
		t.Fatalf("rebuild request: %v", err)
	}
	req.Header = captured.Header.Clone()

	if ok, verrs := v.ValidateHttpRequestSync(req); !ok {
		reportViolations(t, "request", verrs)
	}

	// Also validate the response body the client accepts, so the SubmitResponse
	// struct can't drift from the documented schema.
	resp := &http.Response{
		StatusCode: http.StatusAccepted,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(bytes.NewReader([]byte(
			`{"sbom_id":"sb-1","image_ref":"alpine@sha256:` + zeros64 +
				`","digest":"sha256:` + zeros64 + `","format":"cyclonedx","existing":false}`))),
	}
	if ok, verrs := v.ValidateHttpResponse(req, resp); !ok {
		reportViolations(t, "response", verrs)
	}
}

// TestReads_ConformToOpenAPI validates that representative GET responses the
// read clients decode conform to the DevRadar OpenAPI contract, so the response
// structs in models.go / reads.go cannot silently drift from the documented
// schemas. Each case pairs an endpoint path with a JSON body the client accepts.
func TestReads_ConformToOpenAPI(t *testing.T) {
	spec, err := os.ReadFile("testdata/openapi.yaml")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	doc, err := libopenapi.NewDocument(spec)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	v, errs := validator.NewValidator(doc)
	if len(errs) > 0 {
		t.Fatalf("build validator: %v", errs)
	}
	if ok, verrs := v.ValidateDocument(); !ok {
		t.Fatalf("spec itself is invalid: %v", verrs)
	}

	cases := []struct {
		name string
		path string
		body string
	}{
		{
			name: "GetSBOM",
			path: "/v1/sboms/sb-1",
			body: `{"sbom_id":"sb-1","image_ref":"alpine@sha256:` + zeros64 +
				`","digest":"sha256:` + zeros64 + `","format":"cyclonedx","status":"active",` +
				`"verification_status":"verified","counts":{"critical":1,"total":3,"relevant":1}}`,
		},
		{
			name: "Findings",
			path: "/v1/sboms/sb-1/findings",
			body: `{"next_cursor":"c2","min_severity":"high","findings":[` +
				`{"scanner":"grype","exposure":"CVE-2024-1234","package":"openssl","version":"3.0.0",` +
				`"severity":"high","score":7.5,"is_fixed":true,"epss":0.4,"epss_pct":0.9,"kev":true,"vex_status":""}]}`,
		},
		{
			name: "Images",
			path: "/v1/images",
			body: `{"min_severity":"medium","images":[{"repository":"repo/a","sbom_count":2,` +
				`"digest_count":1,"versions":["v1"],"latest_at":"2024-01-01T00:00:00Z",` +
				`"counts":{"total":5},"fixable":2,"failures":0}]}`,
		},
		{
			name: "FleetLicenses",
			path: "/v1/licenses",
			body: `{"families":[{"key":"MIT","count":10}],"categories":[{"key":"permissive","count":10}],` +
				`"packages":10,"unlicensed":1,"violations":0}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://devradar.thingz.io"+tc.path, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader([]byte(tc.body))),
			}
			if ok, verrs := v.ValidateHttpResponse(req, resp); !ok {
				reportViolations(t, tc.name+" response", verrs)
			}
		})
	}
}

// reportViolations fails t with each OpenAPI validation error, including nested
// schema reasons.
func reportViolations(t *testing.T, kind string, verrs []*errors.ValidationError) {
	t.Helper()
	for _, ve := range verrs {
		t.Errorf("%s violates OpenAPI contract: %s — %s", kind, ve.Message, ve.Reason)
		for _, sv := range ve.SchemaValidationErrors {
			t.Errorf("  schema: %s", sv.Reason)
		}
	}
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"
