package client

// Models mirror the DevRadar OpenAPI response schemas
// (internal/client/testdata/openapi.yaml). Field names/types are copied from
// the spec; the offline contract test guards against drift.

// SeverityCounts is a per-severity breakdown. Buckets below the requested
// threshold are omitted; unknown is always kept. Total is the overall count;
// Relevant sums the visible buckets.
type SeverityCounts struct {
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Unknown    int `json:"unknown"`
	Total      int `json:"total"`
	Relevant   int `json:"relevant"`
}

// Attestation is the cryptographic verification evidence for an SBOM, present
// only when an attestation has been submitted and evaluated.
type Attestation struct {
	Result             string `json:"result,omitempty"`
	Mode               string `json:"mode,omitempty"`
	Binding            string `json:"binding,omitempty"`
	SubjectDigest      string `json:"subject_digest,omitempty"`
	PredicateType      string `json:"predicate_type,omitempty"`
	CertIdentity       string `json:"cert_identity,omitempty"`
	OIDCIssuer         string `json:"oidc_issuer,omitempty"`
	KeyID              string `json:"key_id,omitempty"`
	TransparencyLogRef string `json:"transparency_log_ref,omitempty"`
	VerifierVersion    string `json:"verifier_version,omitempty"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	FailureReason      string `json:"failure_reason,omitempty"`
	VerifiedAt         string `json:"verified_at,omitempty"`
}

// SBOMDetail is the metadata and severity breakdown for one SBOM.
type SBOMDetail struct {
	SBOMID             string         `json:"sbom_id"`
	ImageRef           string         `json:"image_ref"`
	Digest             string         `json:"digest"`
	Format             string         `json:"format"`
	SpecVersion        string         `json:"spec_version"`
	Tool               string         `json:"tool"`
	ToolVersion        string         `json:"tool_version"`
	Status             string         `json:"status"`
	VerificationStatus string         `json:"verification_status"`
	SubmittedAt        string         `json:"submitted_at"`
	GeneratedAt        string         `json:"generated_at"`
	Counts             SeverityCounts `json:"counts"`
	Attestation        *Attestation   `json:"attestation,omitempty"`
}

// Finding is a current vulnerability finding, with EPSS/KEV overlays joined
// when available.
type Finding struct {
	Scanner   string  `json:"scanner"`
	Exposure  string  `json:"exposure"`
	Package   string  `json:"package"`
	Version   string  `json:"version"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	IsFixed   bool    `json:"is_fixed"`
	EPSS      float64 `json:"epss"`
	EPSSPct   float64 `json:"epss_pct"`
	KEV       bool    `json:"kev"`
	VEXStatus string  `json:"vex_status"`
}

// Event is a single entry in an SBOM's change log.
type Event struct {
	Scanner    string  `json:"scanner"`
	EventType  string  `json:"event_type"`
	Exposure   string  `json:"exposure"`
	Package    string  `json:"package"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	Cause      string  `json:"cause"`
	OccurredAt string  `json:"occurred_at"`
}

// TimelineEvent is an Event across an image's digests, carrying the digest and
// sbom_id it occurred on.
type TimelineEvent struct {
	Digest     string  `json:"digest"`
	SBOMID     string  `json:"sbom_id"`
	Scanner    string  `json:"scanner"`
	EventType  string  `json:"event_type"`
	Exposure   string  `json:"exposure"`
	Package    string  `json:"package"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	Cause      string  `json:"cause"`
	OccurredAt string  `json:"occurred_at"`
}

// Failure is a recent scan failure (a scanner errored or returned nothing).
type Failure struct {
	Scanner    string `json:"scanner"`
	Stage      string `json:"stage"`
	Error      string `json:"error"`
	OccurredAt string `json:"occurred_at"`
}

// PackageLicense is one package's licenses and the tenant policy verdict.
type PackageLicense struct {
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	PURL      string   `json:"purl"`
	Licenses  []string `json:"licenses"`
	Category  string   `json:"category"`
	Violation bool     `json:"violation"`
	Reason    string   `json:"reason"`
}

// RepoImage is one tracked image, grouped by repository and risk-ranked.
type RepoImage struct {
	Repository  string         `json:"repository"`
	SBOMCount   int            `json:"sbom_count"`
	DigestCount int            `json:"digest_count"`
	Versions    []string       `json:"versions"`
	LatestAt    string         `json:"latest_at"`
	Counts      SeverityCounts `json:"counts"`
	Fixable     int            `json:"fixable"`
	Failures    int            `json:"failures"`
}

// Image is one submitted SBOM (version/digest) for a repository.
type Image struct {
	SBOMID      string         `json:"sbom_id"`
	ImageRef    string         `json:"image_ref"`
	Digest      string         `json:"digest"`
	Format      string         `json:"format"`
	SubmittedAt string         `json:"submitted_at"`
	Counts      SeverityCounts `json:"counts"`
	Failures    int            `json:"failures"`
}

// LicenseCount is a keyed count in the fleet license rollup.
type LicenseCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// FleetLicenseStats is the tenant's fleet-wide license landscape.
type FleetLicenseStats struct {
	Families   []LicenseCount `json:"families"`
	Categories []LicenseCount `json:"categories"`
	Packages   int            `json:"packages"`
	Unlicensed int            `json:"unlicensed"`
	Violations int            `json:"violations"`
}

// VEXResult is the outcome of submitting an OpenVEX document.
type VEXResult struct {
	DocumentID string `json:"document_id"`
	Statements int    `json:"statements"`
	Matched    int    `json:"matched"`
	Unmatched  int    `json:"unmatched"`
	Skipped    int    `json:"skipped"`
	Note       string `json:"note"`
}

// ListOptions carries the shared list query parameters. Zero-valued fields are
// omitted from the request, letting the service apply its defaults.
type ListOptions struct {
	MinSeverity string
	Sort        string
	Dir         string
	Cursor      string
	Limit       int
}

// page is the shared list envelope: NextCursor is present only when more pages
// exist.
type page struct {
	NextCursor string `json:"next_cursor"`
}
