# Releasing

Releases are cut by pushing a semver tag. Everything after that is automated.

This document is for maintainers. Contributors do not need it — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Cutting a release

```shell
make bump-patch   # v1.2.3 -> v1.2.4
make bump-minor   # v1.2.3 -> v1.3.0
make bump-major   # v1.2.3 -> v2.0.0
```

`tools/bump` refuses to tag from a branch other than `main`, refuses a dirty or
untracked-file-carrying tree, refuses when the branch is ahead of or behind
`origin`, and runs `make qualify` before it tags anything. A tag names bytes
other people will verify against, and it cannot be taken back, so the checks are
enforced rather than listed. `SKIP_QUALIFY=1` exists for re-tagging a commit
already known to be green; it is not for saving time.

The branch and the tag are pushed with `git push --atomic`, so a race that
rejects one rejects both — the remote never ends up carrying a tag that points
at a commit nobody can fetch.

## What happens on the tag

`.github/workflows/release.yaml` runs on a `v[0-9]+.[0-9]+.[0-9]+*` tag. It
re-qualifies the tagged commit here and then hands everything else to
[`release-go.yaml`](https://github.com/thingzio/actions/blob/main/.github/workflows/release-go.yaml)
in `thingzio/actions`, pinned by commit SHA:

1. **The full gate runs first**, here, against the tagged tree rather than
   trusting that `main` was green when it was merged: format check, `go vet`,
   golangci-lint, the race-detector suite with its coverage floor, and
   ShellCheck over the release tooling. A failure aborts the release before
   anything is built.
2. **Build.** goreleaser builds `devradarctl` for linux and darwin on amd64 and
   arm64 (`CGO_ENABLED=0`, `-trimpath`, commit-timestamped), a checksum file
   covering every artifact, and a CycloneDX SBOM per archive. This job holds no
   signing identity.
3. **Sign.** In a separate job that runs no code from this repository, `cosign`
   signs the checksum file with a keyless Sigstore signature. Signing the
   checksums rather than each archive means one signature covers the release and
   there is exactly one thing to verify. Before signing, that job re-downloads
   every asset on the release and re-derives its digest, so it never signs a
   checksum file describing something the release does not carry.
4. **Attest.** Build provenance is attested in the same isolated job.
5. **Verify.** `cosign verify-blob` checks the signature that was just produced,
   requiring the shared workflow's own identity. A signature nobody checks is a
   signature nobody knows is broken, and this fails the release rather than
   publishing an unverifiable one.
6. **Publish.** The release is created as a draft and flipped to published only
   after verification succeeds, so a release is never visible before its
   signature has been checked.

**The signer is `thingzio/actions`, not this repository.** That is the point of
the split: because the job holding the signing identity runs no code from here,
goreleaser hooks in this repository cannot reach it, and the provenance reaches
SLSA Build Level 3 rather than 2.

Releases cut before this migration were built and signed inside this
repository's own workflow and verify against that identity instead. Their
release notes carry the commands that match them.

The Homebrew cask is pushed to `thingzio/homebrew-tap` during step 2, so
`brew install thingzio/tap/devradarctl` picks up the new version.

## Verifying a release

Provenance, naming the shared workflow as the builder:

```shell
gh attestation verify devradarctl_1.2.3_darwin_arm64.tar.gz \
  --repo thingzio/devradarctl \
  --signer-workflow thingzio/actions/.github/workflows/release-go.yaml
```

The signature over the checksum file, which commits to every artifact by digest:

```shell
cosign verify-blob checksums.txt \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp '^https://github\.com/thingzio/actions/\.github/workflows/release-go\.yaml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then confirm the checksum file describes the artifact you downloaded:

```shell
sha256sum -c checksums.txt --ignore-missing
```

The checksum asset is named `checksums.txt` rather than
`devradarctl_checksums.txt` so that it matches the signature covering it. The
shared workflow normalises whatever goreleaser produced before signing and
publishes `checksums.txt.bundle`; any other `checksum.name_template` leaves a
release whose signature filename does not match the file it signs. Releases up
to and including `v0.3.1` used the old name.

`.github/workflows/verify-release.yaml` runs all of the above against the latest
release every Monday, so a break in this path surfaces on a schedule rather than
in someone's pipeline.

`--signer-workflow` is the check that matters. Omitting it accepts provenance
from any workflow in the repository, which is exactly the claim the isolated
signing job exists to make stronger.

## Release candidates

A prerelease tag (`v0.1.0-rc.1`) exercises the whole path without publishing the
Homebrew cask: `prerelease: auto` detects it and `skip_upload: auto` skips the
cask for prereleases. Useful before a first release, or any release that changes
the pipeline.

The final tag goes on a *later* commit than its candidate. The shared workflow
tells goreleaser the triggering tag explicitly via `GORELEASER_CURRENT_TAG`, so
two tags on one commit no longer confuse it — but a release and its candidate
pointing at the same tree is still confusing for people.

## The Homebrew tap

The cask is published only when the repository has a `HOMEBREW_DEPLOY_KEY`
secret: a fine-grained PAT with `contents: write` on `thingzio/homebrew-tap`.
Without it goreleaser skips the cask rather than failing, so a release works
before the secret exists and starts publishing the cask once it does.

A cask rather than a formula, because these are prebuilt signed binaries. A
formula would ask Homebrew to build from source, producing a binary nobody
attested to.

One ordering wrinkle: the cask is pushed while the GitHub release is still a
draft, since publication waits for signature verification. A release that fails
verification leaves a cask pointing at a tag that never publishes, and the fix
is to revert that commit in the tap. That is the right trade against publishing
a release nobody checked. Cutting a release candidate first is the cheap way to
find a pipeline problem before a real cask points at a draft.

The cask does not bundle syft. devradarctl shells out to it, and the caveat on
the cask says so.

## Versioning

[Semantic versioning](https://semver.org). Until 1.0, minor versions may carry
breaking changes to flags and output; patch versions do not.

The service API is versioned separately by the DevRadar service itself
(`/v1/...`). A change there is described in
[DEVELOPMENT.md](DEVELOPMENT.md#api-contract), not by this version number.

## If a release goes wrong

**The signing job failed.** Re-run **only the failed jobs**, not the whole
workflow. The signing job keeps the checksum file from the build for seven days
and will re-download the release's assets and re-verify them against it.
Re-running the whole workflow means a second `goreleaser release` against a
release that already exists — survivable, because `release.use_existing_draft`
makes goreleaser reuse the draft rather than open a second one for the same tag,
but there is no reason to rebuild what is already built.

Nothing is public while this is true: the release stays a draft until the
signature verifies.

**The tag exists but the workflow failed.** Fix the problem on `main`, then cut
a new patch version. Do not delete and re-push the tag — someone may already
have consumed it, and a moving tag is worse than a skipped version number.
Version numbers are free.

If the build never got as far as creating the release, deleting the draft and
re-tagging is also fine: a draft is not immutable, a published release is.

**A released version has a serious defect.** Cut a new patch release. There is
no yank mechanism, and the supported-version policy in
[SECURITY.md](SECURITY.md) means only the latest release is maintained anyway.

## Release checklist

Nothing here is enforced by tooling, which is why it is written down:

- [ ] CI is green on the commit being tagged
- [ ] Anything user-visible is reflected in the README
- [ ] `internal/client/testdata/openapi.yaml` matches the deployed service, if
      the API moved since the last release

`make qualify` and the clean-tree, branch, and sync checks are enforced by
`tools/bump`, so they are deliberately absent from this list. A checklist item
that tooling already guarantees is an item people stop reading.
