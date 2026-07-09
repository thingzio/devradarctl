# Development

Contributor guide for `devradarctl`. For user-facing install and usage, see the
[README](README.md).

## Prerequisites

- Go — version pinned in [`.go-version`](.go-version).
- [`golangci-lint`](https://golangci-lint.run), [`goreleaser`](https://goreleaser.com),
  and [`syft`](https://github.com/anchore/syft) for linting, release builds, and
  SBOM generation. Pinned versions live in [`.settings.yaml`](.settings.yaml).
- [`yq`](https://github.com/mikefarah/yq) — the Makefile reads tool versions and
  thresholds from `.settings.yaml` through it.
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) for `make vulncheck`
  (`go install golang.org/x/vuln/cmd/govulncheck@latest`).

## Common tasks

```sh
make build          # build ./bin/devradarctl
make install        # install to GOBIN
make test           # race detector + coverage profile
make test-coverage  # test + enforce the coverage threshold
make lint           # go vet + golangci-lint
make fmt-check      # gofmt check, no mutation (CI-friendly)
make vulncheck      # govulncheck ./...
make qualify        # full local gate: fmt-check + test-coverage + lint (mirrors CI)
make tidy           # go fmt + go mod tidy
make upgrade        # go get -u ./... + tidy
make snapshot       # local goreleaser build, no publish
make info           # project + resolved tool versions
```

Run a single test:

```sh
go test -run TestName ./internal/...
```

Run `make qualify` before opening a PR — it is the same gate CI enforces.

## Project layout

Thin `main.go` delegates to `internal/`; nothing is meant for external import,
hence `internal/` rather than `pkg/`.

- `main.go` — sets `version`/`commit`/`date` (via ldflags), wires SIGINT/SIGTERM,
  calls `cli.New(...).Run`.
- `internal/cli` — [urfave/cli v3](https://github.com/urfave/cli) command tree.
  - `root.go` — root command, global `--debug`/`--log-json`, `Before` hook installs the logger.
  - `sbom.go` — `sbom` command; `generateSBOM` (pin digest → syft → write) is shared with submit.
  - `submit.go` — `submit` command; token resolution (`DEVRADAR_TOKEN` → piped stdin), file vs image mode.
  - `flags.go` — shared flag constants and `syftFlags()`.
- `internal/sbom` — SBOM domain logic.
  - `ref.go` — `SplitRef`/`Repository`/`Tag` image-reference parsing.
  - `digest.go` — manifest digest resolution in-process via `go-containerregistry` (no `crane` binary).
  - `generate.go` — shells out to `syft` (`-q --scope all-layers -o cyclonedx-json <ref>`); `EnsureSyft` fails fast if absent.
- `internal/client` — HTTP client for `POST /v1/sboms`.
- `internal/logging` — slog setup; `warn` default, `--debug` → debug, `--log-json` → JSON.

## Conventions

- **Logging default is `warn`** (quiet CLI). `--debug` lifts it to debug.
- Env vars use the `DEVRADAR_*` prefix.
- SBOMs are generated against a **digest-pinned** reference so the document
  carries the manifest digest DevRadar keys on.

## Version & tool sources

- [`.go-version`](.go-version) — Go toolchain version, read by the Makefile and CI.
- [`.settings.yaml`](.settings.yaml) — pinned tool versions (goreleaser,
  golangci-lint, syft) and quality thresholds, read via `yq`. Single source of
  truth shared by the Makefile and workflows; carries `# renovate:` annotations.

## API contract

`POST {base}/v1/sboms`, header `Authorization: Bearer <token>`. Success is
`202 Accepted` (idempotent — a re-submit returns the existing row with
`existing: true`). Only `sbom` is required:

| Field          | Req? | Purpose                                                   |
| -------------- | ---- | --------------------------------------------------------- |
| `sbom`         | yes  | base64 SBOM bytes (CycloneDX or SPDX; gzip allowed)       |
| `image_ref`    | no   | override the image reference (`repo@sha256:…`)            |
| `version`      | no   | the image tag (e.g. `v1.20.2`); else parsed from image_ref |
| `generated_at` | no   | RFC3339 timestamp override                                |
| `labels`       | no   | grouping labels (e.g. `team-x`, `prod`)                   |

devradarctl sets `sbom`, `image_ref`, `version`, and `labels`; it relies on the
SBOM's own `generated_at`, so it does not send that field.

Response: `{ sbom_id, image_ref, digest, format, existing }`, where `format` is
`cyclonedx` or `spdx`.

**Source of truth** is devradar's OpenAPI spec,
`pkg/server/static/openapi.yaml` (implementation notes in `IMPLEMENTATION.md`).
A verbatim copy is vendored at `internal/client/testdata/openapi.yaml` and the
client's request/response are validated against it in
`internal/client/contract_test.go`. `TestOpenAPISpec_IsCurrent` fails if the
vendored copy drifts from devradar's (when that checkout is reachable, or
`DEVRADAR_OPENAPI` points at it). Refresh the copy when the API changes:

```sh
cp ../devradar/pkg/server/static/openapi.yaml internal/client/testdata/openapi.yaml
```

## Releasing

Releases are cut by pushing a semver tag, which triggers
[`.github/workflows/release.yaml`](.github/workflows/release.yaml):

```sh
make bump-patch   # v0.1.2 -> v0.1.3: signed tag + push
make bump-minor   # v0.1.2 -> v0.2.0
make bump-major   # v0.1.2 -> v1.0.0
```

Each of these requires a clean, fully-pushed tree (`tools/bump` enforces it).
The workflow re-qualifies from scratch, then runs `goreleaser`, which:

- builds binaries for linux/darwin × amd64/arm64 (`CGO_ENABLED=0 -trimpath`),
- attaches sha256 checksums and per-archive CycloneDX SBOMs,
- publishes a full (non-draft) GitHub release,
- attaches SLSA build provenance via `actions/attest-build-provenance`.

Verify a downloaded artifact's provenance:

```sh
gh attestation verify <archive> --repo thingzio/devradarctl
```

### CI

- [`qualify.yaml`](.github/workflows/qualify.yaml) — reusable gate (fmt-check, vet, lint, test + coverage).
- [`test.yaml`](.github/workflows/test.yaml) — runs `qualify` on push/PR to `main`.
- [`release.yaml`](.github/workflows/release.yaml) — on a `v*` tag: re-qualifies, then releases.

Action SHAs are pinned; jobs use least-privilege `permissions` and
`persist-credentials: false`. Dependencies are not vendored — CI relies on the
Go module cache.

### Homebrew tap

The `.goreleaser.yaml` cask is dormant until the tap repo
(`thingzio/homebrew-devradarctl`) exists and the release workflow provides a
`HOMEBREW_DEPLOY_KEY` secret. `skip_upload` is templated on that key, so no tap
API call is made while it is absent.
