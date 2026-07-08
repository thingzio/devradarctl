// Package client is a thin HTTP client for the DevRadar SBOM ingest API.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public DevRadar service used when none is configured.
const DefaultBaseURL = "https://devradar.thingz.io"

// defaultTimeout bounds a single submit round-trip.
const defaultTimeout = 60 * time.Second

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
	// Version is the human tag (e.g. "v1.20.2"), optional.
	Version string
	// Tags are tenant grouping labels (e.g. "team-x", "prod"), optional.
	Tags []string
}

// SubmitResponse mirrors the POST /v1/sboms response body.
type SubmitResponse struct {
	SBOMID   string `json:"sbom_id"`
	ImageRef string `json:"image_ref"`
	Digest   string `json:"digest"`
	Format   string `json:"format"`
	Existing bool   `json:"existing"`
}

// wireRequest is the JSON shape sent to the service.
type wireRequest struct {
	SBOM     string   `json:"sbom"`
	ImageRef string   `json:"image_ref,omitempty"`
	Version  string   `json:"version,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// Submit posts an SBOM to {baseURL}/v1/sboms and returns the decoded response.
// A non-2xx status is returned as an error including the response body.
func (c *Client) Submit(ctx context.Context, in SubmitRequest) (*SubmitResponse, error) {
	if len(in.SBOM) == 0 {
		return nil, fmt.Errorf("sbom is empty")
	}
	body, err := json.Marshal(wireRequest{
		SBOM:     base64.StdEncoding.EncodeToString(in.SBOM),
		ImageRef: in.ImageRef,
		Version:  in.Version,
		Tags:     in.Tags,
	})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	url := c.baseURL + "/v1/sboms"
	slog.Debug("submitting SBOM", "url", url, "image_ref", in.ImageRef, "version", in.Version, "tags", in.Tags, "bytes", len(in.SBOM))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("submit to %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("submission failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out SubmitResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response (HTTP %d): %w", resp.StatusCode, err)
	}
	return &out, nil
}
