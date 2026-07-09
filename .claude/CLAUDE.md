# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`devradarctl` — CLI for the [DevRadar](https://github.com/thingzio/devradar) service.
Module `github.com/thingzio/devradarctl`. MIT-licensed (thinkz.io). Wraps the
SBOM generate + submit workflow that previously lived in devradar's
`tools/sbom-submit`.

## Commands

- `make build` — build `./bin/devradarctl` (ldflags inject version/commit/date).
- `make test` — race + coverage profile. Single test: `go test -run TestName ./internal/...`.
- `make test-coverage` — test + enforce `quality.coverage_threshold` from `.settings.yaml`.
- `make lint` — `go vet` + `golangci-lint` (config in `.golangci.yaml`, v2 schema).
- `make fmt-check` — CI-friendly gofmt check (no mutation).
- `make vulncheck` — `govulncheck ./...`.
- `make qualify` — full local gate: fmt-check + test-coverage + lint (mirrors CI).
- `make upgrade` — `go get -u ./...` + tidy.
- `make snapshot` — local `goreleaser` snapshot build (`--skip=sbom`).
- `make bump-{patch,minor,major}` — tag + push a semver release via `tools/bump`, triggering the release workflow.

## Version & tool sources

- `.go-version` — Go toolchain version (read by Makefile + all CI via `cat`).
- `.settings.yaml` — pinned tool versions (goreleaser, golangci-lint, syft) and
  quality thresholds, read via `yq`. Single source of truth shared by the Makefile and workflows; carries `# renovate:` annotations. Mirrors the devradar convention.

## CI / release

- `.github/workflows/qualify.yaml` — reusable gate (fmt-check, vet, lint, test+coverage).
- `test.yaml` — runs `qualify` on push/PR to main.
- `release.yaml` — on `v*` tag: re-runs `qualify` from scratch, then goreleaser
  (binaries + checksums + SBOMs, guarded Homebrew cask), then
  `actions/attest-build-provenance` (keyless SLSA provenance over the archives +
  checksums; verify with `gh attestation verify <file> --repo thingzio/devradarctl`).
- Action SHAs are pinned; jobs use least-privilege `permissions` and `persist-credentials: false`.
- No vendoring — CI relies on the Go module cache (deliberate: go-containerregistry's tree is large).

## Architecture

Thin `main.go` → `internal/cli`. Nothing is meant for external import, hence
`internal/` (not `pkg/`).

- `main.go` — sets `version/commit/date` (ldflags), wires SIGINT/SIGTERM context, calls `cli.New(...).Run`.
- `internal/cli` — urfave/cli **v3** command tree.
  - `root.go` — root command, global `--debug`/`--log-json` flags, `Before` hook installs the logger.
  - `sbom.go` — `sbom` command; `generateSBOM` (pin digest → syft → write) is shared with submit.
  - `submit.go` — `submit` command; `resolveToken` (env `DEVRADAR_TOKEN` → piped stdin), file vs image mode (mutually exclusive).
  - `flags.go` — shared flag constants and `syftFlags()`.
- `internal/sbom` — SBOM domain logic.
  - `ref.go` — `SplitRef`/`Repository`/`Tag` (ported from devradar `pkg/sbom/ref.go`).
  - `digest.go` — manifest digest resolution **in-process** via `go-containerregistry` (crane lib); no `crane` binary needed.
  - `generate.go` — shells out to `syft` (`-q --scope all-layers -o cyclonedx-json <ref>`); `EnsureSyft` fails fast if absent.
- `internal/client` — HTTP client for `POST /v1/sboms` (Bearer auth, base64 `sbom`, optional `image_ref`/`version`/`labels`).
- `internal/logging` — slog setup; **warn** default level, `--debug` → debug, `--log-json` → JSON handler.

## Key conventions

- **Logging default is warn** (quiet CLI), unlike the devradar server (info). `--debug` lifts to debug.
- Env vars use the `DEVRADAR_*` prefix (matches the devradar server), not the old `DR_*` from `tools/sbom-submit`.
- SBOMs are generated against a **digest-pinned** reference so the document carries the manifest digest DevRadar keys on.

## API contract

`POST {base}/v1/sboms`, header `Authorization: Bearer <token>`, body
`{ "sbom": <base64>, "image_ref"?, "version"?, "labels"?[], "generated_at"? }`.
The CLI sends `sbom`/`image_ref`/`version`/`labels` only. Success is `202`;
response `{ sbom_id, image_ref, digest, format, existing }` (`format` is
`cyclonedx`|`spdx`). Source of truth: devradar's OpenAPI spec
`pkg/server/static/openapi.yaml`, vendored at `internal/client/testdata/openapi.yaml`
and enforced by `internal/client/contract_test.go`. Default base URL
`https://devradar.thingz.io`.

## Release

GoReleaser (`.goreleaser.yaml`): single build, linux+darwin × amd64+arm64,
`CGO_ENABLED=0 -trimpath`, tar.gz archives, sha256 checksums, per-archive SBOMs,
draft GitHub release, guarded Homebrew tap (`thingzio/homebrew-devradarctl`).
