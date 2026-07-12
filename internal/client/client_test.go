package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubmit_Success(t *testing.T) {
	const token = "tok-123"
	sbomDoc := []byte(`{"bomFormat":"CycloneDX"}`)

	var gotAuth, gotContentType, gotPath string
	var gotBody wireRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusAccepted) // 202, per the OpenAPI spec
		_ = json.NewEncoder(w).Encode(SubmitResponse{SBOMID: "sb-1", Format: "cyclonedx", ImageRef: "alpine@sha256:x"})
	}))
	defer srv.Close()

	c := New(srv.URL, token)
	resp, err := c.Submit(context.Background(), SubmitRequest{
		SBOM:     sbomDoc,
		ImageRef: "alpine@sha256:x",
		Version:  "3.20",
		Labels:   []string{"team-x", "prod"},
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	if gotPath != "/v1/sboms" {
		t.Errorf("path = %q, want /v1/sboms", gotPath)
	}
	if gotAuth != "Bearer "+token {
		t.Errorf("Authorization = %q, want Bearer %s", gotAuth, token)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	wantB64 := base64.StdEncoding.EncodeToString(sbomDoc)
	if gotBody.SBOM != wantB64 {
		t.Errorf("body.sbom = %q, want base64 %q", gotBody.SBOM, wantB64)
	}
	if gotBody.ImageRef != "alpine@sha256:x" || gotBody.Version != "3.20" {
		t.Errorf("body image_ref/version = %q/%q", gotBody.ImageRef, gotBody.Version)
	}
	if len(gotBody.Labels) != 2 {
		t.Errorf("body.labels = %v, want 2 labels", gotBody.Labels)
	}
	if resp.SBOMID != "sb-1" || resp.Format != "cyclonedx" {
		t.Errorf("resp = %+v", resp)
	}
}

// TestSubmit_Attestation asserts the attestation bundle is base64-encoded onto
// the `attestation` wire field and the verification_status is read back.
func TestSubmit_Attestation(t *testing.T) {
	bundle := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`)
	var gotBody wireRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(SubmitResponse{
			SBOMID: "sb-1", Format: "cyclonedx", VerificationStatus: "verified",
		})
	}))
	defer srv.Close()

	resp, err := New(srv.URL, "tok").Submit(context.Background(), SubmitRequest{
		SBOM:        []byte(`{"bomFormat":"CycloneDX"}`),
		Attestation: bundle,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(bundle); gotBody.Attestation != want {
		t.Errorf("body.attestation = %q, want base64 %q", gotBody.Attestation, want)
	}
	if resp.VerificationStatus != "verified" {
		t.Errorf("VerificationStatus = %q, want verified", resp.VerificationStatus)
	}
}

// TestSubmit_NoAttestationOmitsField ensures the field is omitted when no bundle
// is supplied (omitempty), so existing submissions are unchanged on the wire.
func TestSubmit_NoAttestationOmitsField(t *testing.T) {
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(SubmitResponse{SBOMID: "sb-1"})
	}))
	defer srv.Close()

	if _, err := New(srv.URL, "tok").Submit(context.Background(), SubmitRequest{
		SBOM: []byte(`{"bomFormat":"CycloneDX"}`),
	}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if strings.Contains(string(rawBody), "attestation") {
		t.Errorf("wire body should omit attestation when none supplied: %s", rawBody)
	}
}

func TestSubmit_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad token", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := New(srv.URL, "nope")
	_, err := c.Submit(context.Background(), SubmitRequest{SBOM: []byte("{}")})
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
}

func TestSubmit_EmptySBOM(t *testing.T) {
	c := New("http://example.invalid", "tok")
	if _, err := c.Submit(context.Background(), SubmitRequest{}); err == nil {
		t.Fatal("expected error on empty SBOM, got nil")
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	if c := New("", "tok"); c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c := New("https://x.example/", "tok"); c.baseURL != "https://x.example" {
		t.Errorf("trailing slash not trimmed: %q", c.baseURL)
	}
}
