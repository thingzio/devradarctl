package sbom

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// PinnedRef resolves image's manifest digest against its registry and returns a
// digest-pinned reference of the form "repo@sha256:…". Pinning by digest (not
// tag) is what makes the generated SBOM carry the manifest digest the DevRadar
// service needs to identify the image unambiguously.
//
// If image already carries a digest, it is normalized and reused without a
// network call. Registry auth uses the ambient Docker keychain (respects
// docker login / credential helpers).
func PinnedRef(ctx context.Context, image string) (string, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return "", fmt.Errorf("parse image reference %q: %w", image, err)
	}

	// Already digest-pinned? Reuse it — no registry round-trip needed.
	if d, ok := ref.(name.Digest); ok {
		return d.Repository.Name() + "@" + d.DigestStr(), nil
	}

	desc, err := remote.Head(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return "", fmt.Errorf("resolve digest for %q: %w", image, err)
	}
	return ref.Context().Name() + "@" + desc.Digest.String(), nil
}

// Digest resolves and returns just the manifest digest (e.g. "sha256:…") for
// image, without the repository prefix.
func Digest(ctx context.Context, image string) (v1.Hash, error) {
	ref, err := name.ParseReference(image)
	if err != nil {
		return v1.Hash{}, fmt.Errorf("parse image reference %q: %w", image, err)
	}
	if d, ok := ref.(name.Digest); ok {
		return v1.NewHash(d.DigestStr())
	}
	desc, err := remote.Head(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return v1.Hash{}, fmt.Errorf("resolve digest for %q: %w", image, err)
	}
	return desc.Digest, nil
}
