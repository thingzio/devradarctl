# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`devradarctl` — CLI for the DevRadar service (`https://devradar.thingz.io`).
Module `github.com/thingzio/devradarctl`. MIT-licensed (thinkz.io). It wraps the
SBOM generate + submit workflow **and** DevRadar's read API. Command groups:
`sbom` (generate + per-SBOM reads: get/findings/events/failures/licenses/archive),
`submit`, `images` (list/timeline/sboms), `licenses` (fleet rollup), `vex`
(submit/list), and `watch`.

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
  quality thresholds, read via `yq`. Single source of truth shared by the Makefile and workflows; carries `# renovate:` annotations.

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

- `main.go` — sets `version/commit/date` (ldflags), wires SIGINT/SIGTERM context, calls `cli.New(...).Run`. Owns the exit code: honors an `ExitCoder` (the findings gate) via `errors.AsType`, else 1 on error.
- `internal/cli` — urfave/cli **v3** command tree. Root sets `ExitErrHandler` to a no-op so `main` owns the process exit (the default handler calls `os.Exit` from inside `Run`).
  - `root.go` — root command, global `--debug`/`--log-json` flags, `Before` hook installs the logger; registers all command groups.
  - `sbom.go` — `sbom` **group**: `generate` subcommand (local gen; `-o` = file path) plus read subcommands; `generateSBOM` (pin digest → syft → write) is shared with submit.
  - `submit.go` — `submit` command; `resolveToken` (env `DEVRADAR_TOKEN` → piped stdin), file vs image mode (mutually exclusive).
  - `reads.go` — `apiClient`/`firstArg`/`listOptions`/`baseURLFlag`/`listFlags` helpers and the `sbom get/events/failures/licenses/archive` actions.
  - `findings.go` — `sbom findings` action + `--exit-code` CI gate (`gateBreach`, exit code 2).
  - `images.go`, `licenses.go`, `vex.go`, `watch.go` — the remaining command groups.
  - `output.go` — `outputFlag()`/`asJSON`/`render` (JSON vs `text/tabwriter` table) + `moreHint` paging nudge.
  - `format.go` — table formatters (`severitySummary`, `findingTable`, …) and the `confirm` prompt.
  - `flags.go` — shared flag constants and `syftFlags()`.
- `internal/sbom` — SBOM domain logic.
  - `ref.go` — `SplitRef`/`Repository`/`Tag` image-reference parsing.
  - `digest.go` — manifest digest resolution **in-process** via `go-containerregistry` (crane lib); no `crane` binary needed.
  - `generate.go` — shells out to `syft` (`-q --scope all-layers -o cyclonedx-json <ref>`); `EnsureSyft` fails fast if absent. stdout is captured through a `capBuffer` bounded to 20 MiB so a runaway generation can't exhaust memory.
- `internal/client` — HTTP client for the DevRadar API.
  - `client.go` — `Submit` (`POST /v1/sboms`, Bearer auth, base64 `sbom`, optional `image_ref`/`version`/`labels`/`attestation`); enforces the API size caps client-side (`MaxSBOMBytes` 20 MiB, `MaxVEXBytes` 5 MiB, `MaxAttestationBytes`).
  - `http.go` — shared `doOnce`/`do`/`get` helpers. Responses are read via `io.LimitReader` (`maxResponseBytes`). **GET is retried** (bounded, exp backoff + jitter, honors `Retry-After`) on transport errors / 5xx / 429; writes are never retried.
  - `error.go` — typed `APIError{StatusCode, Message}` parsed from the `{"error":...}` envelope; `TooManyRequests()` helper.
  - `reads.go` — read methods (`GetSBOM`, `Findings`, `Events`, `Failures`, `Licenses`, `ArchiveSBOM`, `Images`, `Timeline`, `ImageSBOMs`, `FleetLicenses`, `SubmitVEX`, `ListVEX`); list methods take a `ListOptions` and return the page + `NextCursor`.
  - `models.go` — response structs mirroring the spec schemas.
- `internal/logging` — slog setup; **warn** default level, `--debug` → debug, `--log-json` → JSON handler.

Output convention for reads: all output routes through `c.Writer`/`c.ErrWriter` (never `os.Stdout`) for testability. Default human table (one page + a "more available" hint on stderr); `--output json` (`-o json`) emits raw JSON and auto-follows **all** pages (`--all` forces full paging for tables too). `sbom findings --exit-code` also forces full paging so the CI gate never misses a finding on a later page. Shared flags fail closed (`validateCommon`: output/severity/dir/limit) before any network call.

## Key conventions

- **Logging default is warn** (quiet CLI). `--debug` lifts to debug.
- Env vars use the `DEVRADAR_*` prefix.
- SBOMs are generated against a **digest-pinned** reference so the document carries the manifest digest DevRadar keys on.

## API contract

Submit: `POST {base}/v1/sboms`, header `Authorization: Bearer <token>`, body
`{ "sbom": <base64>, "image_ref"?, "version"?, "labels"?[], "attestation"? }`.
Success is `202`; response `{ sbom_id, image_ref, digest, format, existing,
verification_status }` (`format` is `cyclonedx`|`spdx`). The CLI also wraps the
read surface (`GET /v1/sboms/{id}`(+`/findings`,`/events`,`/failures`,
`/licenses`), `DELETE /v1/sboms/{id}`, `GET /v1/images`(+`/timeline`,`/sboms`),
`GET /v1/licenses`, `GET`/`POST /v1/vex`) — see `internal/client/reads.go`.
Source of truth: the service's public OpenAPI doc at
`https://devradar.thingz.io/openapi.yaml`, vendored at
`internal/client/testdata/openapi.yaml` and enforced by
`internal/client/contract_test.go` (offline: request + representative read
responses) + `spec_sync_test.go` (fetches live, skips under `-short`/offline).
Default base URL `https://devradar.thingz.io`.

## Release

GoReleaser (`.goreleaser.yaml`): single build, linux+darwin × amd64+arm64,
`CGO_ENABLED=0 -trimpath`, tar.gz archives, sha256 checksums, per-archive SBOMs,
draft GitHub release, guarded Homebrew cask into the shared org tap
(`thingzio/homebrew-tap`; install via `brew install thingzio/tap/devradarctl`).
