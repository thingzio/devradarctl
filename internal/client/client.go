// Package client is a thin HTTP client for the DevRadar SBOM ingest API.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public DevRadar service used when none is configured.
const DefaultBaseURL = "https://devradar.thingz.io"

// defaultTimeout bounds a single submit round-trip.
const defaultTimeout = 60 * time.Second

// Size caps mirror the DevRadar API's documented limits, enforced client-side
// so oversized inputs fail fast (before upload) and responses can't exhaust
// memory. MaxSBOMBytes / MaxVEXBytes are decoded-payload ceilings; the wire
// body is larger once base64-encoded, which the server also bounds.
const (
	MaxSBOMBytes        = 20 << 20 // 20 MiB (POST /v1/sboms)
	MaxVEXBytes         = 5 << 20  // 5 MiB (POST /v1/vex)
	MaxAttestationBytes = 10 << 20 // 10 MiB — sigstore bundles are small; generous cap
	maxResponseBytes    = 32 << 20 // 32 MiB — a large findings page plus headroom
)

// Client submits SBOMs to a DevRadar service.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a Client targeting baseURL (trailing slashes trimmed; falls back
// to DefaultBaseURL when empty) authenticating with the given bearer token.
func New(baseURL, token string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{Timeout: defaultTimeout},
	}
}

// SubmitRequest mirrors the POST /v1/sboms request body. Only SBOM is required;
// the rest override the service's own parsing of the SBOM when it is weak.
type SubmitRequest struct {
	// SBOM is the raw (un-encoded) SBOM document. It is base64-encoded on the wire.
	SBOM []byte
	// ImageRef is the digest-pinned image reference (repo@sha256:…), optional.
	ImageRef string
	// Version is the image tag (e.g. "v1.20.2"), optional.
	Version string
	// Labels are tenant grouping labels (e.g. "team-x", "prod"), optional.
	Labels []string
	// Attestation is the raw (un-encoded) sigstore/cosign bundle, optional. When
	// present it is base64-encoded on the wire; the service verifies it (if a
	// trust policy is configured) and reports the outcome in
	// SubmitResponse.VerificationStatus.
	Attestation []byte
}

// SubmitResponse mirrors the POST /v1/sboms response body.
type SubmitResponse struct {
	SBOMID   string `json:"sbom_id"`
	ImageRef string `json:"image_ref"`
	Digest   string `json:"digest"`
	Format   string `json:"format"`
	Existing bool   `json:"existing"`
	// VerificationStatus is the attestation outcome: unverified | verified | failed.
	VerificationStatus string `json:"verification_status"`
}

// wireRequest is the JSON shape sent to the service (POST /v1/sboms).
type wireRequest struct {
	SBOM        string   `json:"sbom"`
	ImageRef    string   `json:"image_ref,omitempty"`
	Version     string   `json:"version,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	Attestation string   `json:"attestation,omitempty"`
}

// Submit posts an SBOM to {baseURL}/v1/sboms and returns the decoded response.
// A non-2xx status is returned as an error including the response body.
func (c *Client) Submit(ctx context.Context, in SubmitRequest) (*SubmitResponse, error) {
	if len(in.SBOM) == 0 {
		return nil, fmt.Errorf("sbom is empty")
	}
	if len(in.SBOM) > MaxSBOMBytes {
		return nil, fmt.Errorf("sbom is %d bytes, exceeds the %d-byte limit", len(in.SBOM), MaxSBOMBytes)
	}
	if len(in.Attestation) > MaxAttestationBytes {
		return nil, fmt.Errorf("attestation is %d bytes, exceeds the %d-byte limit", len(in.Attestation), MaxAttestationBytes)
	}
	wire := wireRequest{
		SBOM:     base64.StdEncoding.EncodeToString(in.SBOM),
		ImageRef: in.ImageRef,
		Version:  in.Version,
		Labels:   in.Labels,
	}
	if len(in.Attestation) > 0 {
		wire.Attestation = base64.StdEncoding.EncodeToString(in.Attestation)
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	slog.Debug("submitting SBOM", "url", c.baseURL+"/v1/sboms", "image_ref", in.ImageRef, "version", in.Version,
		"labels", in.Labels, "bytes", len(in.SBOM), "attestation_bytes", len(in.Attestation))

	var out SubmitResponse
	if err := c.do(ctx, http.MethodPost, "/v1/sboms", nil, bytes.NewReader(body), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
