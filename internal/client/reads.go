package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// apply writes the non-empty ListOptions fields onto q.
func (o ListOptions) apply(q url.Values) {
	if o.MinSeverity != "" {
		q.Set("min_severity", o.MinSeverity)
	}
	if o.Sort != "" {
		q.Set("sort", o.Sort)
	}
	if o.Dir != "" {
		q.Set("dir", o.Dir)
	}
	if o.Cursor != "" {
		q.Set("cursor", o.Cursor)
	}
	if o.Limit > 0 {
		q.Set("limit", strconv.Itoa(o.Limit))
	}
}

// GetSBOM returns metadata and the severity breakdown for one SBOM. When
// minSeverity is non-empty it trims the breakdown.
func (c *Client) GetSBOM(ctx context.Context, id, minSeverity string) (*SBOMDetail, error) {
	q := url.Values{}
	if minSeverity != "" {
		q.Set("min_severity", minSeverity)
	}
	var out SBOMDetail
	if err := c.get(ctx, "/v1/sboms/"+url.PathEscape(id), q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ArchiveSBOM stops tracking an SBOM (idempotent; findings/history retained).
func (c *Client) ArchiveSBOM(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/sboms/"+url.PathEscape(id), nil, nil, nil)
}

// FindingsOptions extends ListOptions with the findings-specific filters.
type FindingsOptions struct {
	ListOptions
	Fixable    bool
	Suppressed bool
}

// FindingsPage is one page of current findings.
type FindingsPage struct {
	page
	Findings []Finding `json:"findings"`
}

// Findings returns current findings for an SBOM at or above the requested
// severity floor, keyset-paginated.
func (c *Client) Findings(ctx context.Context, id string, opts FindingsOptions) (*FindingsPage, error) {
	q := url.Values{}
	opts.apply(q)
	if opts.Fixable {
		q.Set("fixable", "true")
	}
	if opts.Suppressed {
		q.Set("suppressed", "true")
	}
	var out FindingsPage
	if err := c.get(ctx, "/v1/sboms/"+url.PathEscape(id)+"/findings", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EventsPage is one page of an SBOM's change log.
type EventsPage struct {
	page
	Events []Event `json:"events"`
}

// Events returns the change log for one SBOM, newest first, keyset-paginated.
func (c *Client) Events(ctx context.Context, id string, opts ListOptions) (*EventsPage, error) {
	q := url.Values{}
	opts.apply(q)
	var out EventsPage
	if err := c.get(ctx, "/v1/sboms/"+url.PathEscape(id)+"/events", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Failures returns recent scan failures for one SBOM, newest first.
func (c *Client) Failures(ctx context.Context, id string, limit int) ([]Failure, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out struct {
		Failures []Failure `json:"failures"`
	}
	if err := c.get(ctx, "/v1/sboms/"+url.PathEscape(id)+"/failures", q, &out); err != nil {
		return nil, err
	}
	return out.Failures, nil
}

// Licenses returns the per-package license inventory for one SBOM, violations
// first.
func (c *Client) Licenses(ctx context.Context, id string) ([]PackageLicense, error) {
	var out struct {
		Packages []PackageLicense `json:"packages"`
	}
	if err := c.get(ctx, "/v1/sboms/"+url.PathEscape(id)+"/licenses", nil, &out); err != nil {
		return nil, err
	}
	return out.Packages, nil
}

// ImagesOptions extends ListOptions with the image-list filters.
type ImagesOptions struct {
	ListOptions
	Query string // repository name substring (q)
	Label string
}

// ImagesPage is one page of tracked images.
type ImagesPage struct {
	page
	Images []RepoImage `json:"images"`
}

// Images lists the tenant's tracked images, grouped by repository and
// risk-ranked.
func (c *Client) Images(ctx context.Context, opts ImagesOptions) (*ImagesPage, error) {
	q := url.Values{}
	opts.apply(q)
	if opts.Query != "" {
		q.Set("q", opts.Query)
	}
	if opts.Label != "" {
		q.Set("label", opts.Label)
	}
	var out ImagesPage
	if err := c.get(ctx, "/v1/images", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TimelinePage is one page of an image's change history across digests.
type TimelinePage struct {
	page
	Repository string          `json:"repository"`
	Timeline   []TimelineEvent `json:"timeline"`
}

// Timeline returns the change log for one repository across every version and
// digest, newest first.
func (c *Client) Timeline(ctx context.Context, repo string, opts ListOptions) (*TimelinePage, error) {
	q := url.Values{}
	q.Set("repo", repo)
	opts.apply(q)
	var out TimelinePage
	if err := c.get(ctx, "/v1/images/timeline", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImageSBOMsPage is one page of the SBOMs submitted for a repository.
type ImageSBOMsPage struct {
	page
	Repository string  `json:"repository"`
	SBOMs      []Image `json:"sboms"`
}

// ImageSBOMs lists the submitted SBOMs (versions/digests) for a repository,
// newest generation first.
func (c *Client) ImageSBOMs(ctx context.Context, repo string, opts ListOptions) (*ImageSBOMsPage, error) {
	q := url.Values{}
	q.Set("repo", repo)
	opts.apply(q)
	var out ImageSBOMsPage
	if err := c.get(ctx, "/v1/images/sboms", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FleetLicenses returns the tenant's fleet-wide license rollup.
func (c *Client) FleetLicenses(ctx context.Context) (*FleetLicenseStats, error) {
	var out FleetLicenseStats
	if err := c.get(ctx, "/v1/licenses", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListVEX returns the tenant's submitted OpenVEX documents (metadata only).
func (c *Client) ListVEX(ctx context.Context) ([]map[string]any, error) {
	var out struct {
		Documents []map[string]any `json:"documents"`
	}
	if err := c.get(ctx, "/v1/vex", nil, &out); err != nil {
		return nil, err
	}
	return out.Documents, nil
}

// SubmitVEX ingests a raw OpenVEX document (the caller supplies the JSON bytes).
func (c *Client) SubmitVEX(ctx context.Context, doc []byte) (*VEXResult, error) {
	if !json.Valid(doc) {
		return nil, fmt.Errorf("vex document is not valid JSON")
	}
	var out VEXResult
	if err := c.do(ctx, http.MethodPost, "/v1/vex", nil, bytes.NewReader(doc), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
