package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIError_ParsesEnvelope(t *testing.T) {
	e := newAPIError(http.StatusTooManyRequests, []byte(`{"error":"tenant SBOM limit reached"}`))
	if !e.TooManyRequests() {
		t.Error("expected TooManyRequests for 429")
	}
	if e.Message != "tenant SBOM limit reached" {
		t.Errorf("Message = %q", e.Message)
	}
	if !strings.Contains(e.Error(), "429") || !strings.Contains(e.Error(), "tenant SBOM limit") {
		t.Errorf("Error() = %q", e.Error())
	}
}

func TestAPIError_FallsBackToRawBody(t *testing.T) {
	e := newAPIError(http.StatusBadGateway, []byte("upstream boom"))
	if e.Message != "upstream boom" {
		t.Errorf("Message = %q, want raw body", e.Message)
	}
	if e.TooManyRequests() {
		t.Error("502 is not TooManyRequests")
	}
}

// TestSubmit_429ReturnsAPIError asserts a 429 surfaces as a typed *APIError so
// command-level code can branch on it.
func TestSubmit_429ReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"image limit reached"}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").Submit(context.Background(), SubmitRequest{SBOM: []byte(`{}`)})
	if err == nil {
		t.Fatal("expected error on 429")
	}
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok {
		t.Fatalf("error is not *APIError: %T", err)
	}
	if !apiErr.TooManyRequests() || apiErr.Message != "image limit reached" {
		t.Errorf("apiErr = %+v", apiErr)
	}
}
