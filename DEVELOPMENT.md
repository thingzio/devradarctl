# Development

Project internals for `devradarctl`. For user-facing install and usage, see the
[README](README.md); for how to submit a change, see
[CONTRIBUTING.md](CONTRIBUTING.md); for how a release is cut and verified, see
[RELEASING.md](RELEASING.md).

## Prerequisites

- Go — version pinned in [`.go-version`](.go-version).
- `make`, `python3` (for `make notices`), and `git`.

That is the whole list for day-to-day work. `golangci-lint`, `govulncheck`,
`actionlint`, and `gitleaks` install themselves into `bin/tools` at their pinned
versions the first time a target needs them, so a local `make lint` and the CI
lint job run the identical binary.

Three tools are *not* auto-installed:

- [`yamllint`](https://github.com/adrienverge/yamllint) — a Python tool, so it
  is not a `go install`. CI installs the pinned version with pipx; locally,
  `pipx install yamllint==<pin>` then `make lint-yaml`. It is deliberately not
  part of `make qualify`, so committing a Go change does not require it.
- [`syft`](https://github.com/anchore/syft) — devradarctl shells out to it at
  runtime. Tests that need it skip when it is absent; `make tools` does not
  fetch it, but `bin/tools/syft` is a valid target if you want the pinned one.
- [`goreleaser`](https://goreleaser.com) — only `make snapshot` and `make release`
  use it, and both say so when it is missing.

Every first-party Go file carries the Apache-2.0 header. `make license` applies
it to anything missing one; `make license-check` (part of `make qualify`) fails
if a file slipped through.

## Common tasks

```sh
make build          # build ./bin/devradarctl
make install        # install to GOBIN
make test           # race detector + coverage profile
make test-coverage  # test + enforce the coverage threshold
make lint           # go vet + golangci-lint
make lint-actions   # actionlint over .github/workflows
make lint-yaml      # yamllint --strict (needs pipx-installed yamllint)
make fmt-check      # gofmt check, no mutation (CI-friendly)
make license        # apply the Apache-2.0 header to first-party Go files
make license-check  # fail if any first-party Go file is missing it
make secrets        # gitleaks over the working tree and the full history
make vulncheck      # govulncheck ./...
make qualify        # full local gate, mirrors CI
make tidy           # go fmt + go mod tidy + verify + regenerate notices
make notices        # regenerate THIRD_PARTY_NOTICES.md from the build graph
make upgrade        # go get -u ./... + tidy
make tools          # install the pinned dev tools into bin/tools
make snapshot       # local goreleaser build, no publish
make info           # project + resolved tool versions
make clean          # remove build artifacts (keeps the tool cache)
make clean-all      # also remove bin/tools
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

- [`.go-version`](.go-version) — Go toolchain version. Read by `go-version-file`
  in every workflow and by the Makefile, so `actions/setup-go` and a local build
  cannot disagree. It must stay consistent with the `go` directive in `go.mod`.
- [`.versions.yaml`](.versions.yaml) — pinned tool versions (goreleaser,
  golangci-lint, syft, govulncheck) and quality thresholds. Single source of
  truth shared by the Makefile and the workflows; carries `# renovate:`
  annotations.

Neither file has a second copy of its values anywhere. The Makefile parses
`.versions.yaml` with `sed` (no `yq` dependency, so `make help` works on a bare
machine) and CI reads it through the
[`load-versions`](.github/actions/load-versions/action.yaml) composite action.
A version that appears only in a Makefile recipe or only in a workflow step is a
bug: the two drift, and "works on my machine" becomes unreproducible.

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

**Source of truth** is the DevRadar service's own OpenAPI document, published
publicly (no auth) at <https://devradar.thingz.io/openapi.yaml> (human-readable
docs at `/api`). A copy is vendored at `internal/client/testdata/openapi.yaml`;
the client's request/response are validated against it in
`internal/client/contract_test.go`. `TestOpenAPISpec_IsCurrent` fetches the live
spec and fails if the vendored copy has drifted (ignoring the per-deploy
`info.version` stamp) — it is skipped under `-short` and when the service is
unreachable, so the offline contract test still runs. Refresh the copy when the
API changes:

```sh
curl -sS https://devradar.thingz.io/openapi.yaml -o internal/client/testdata/openapi.yaml
```

Point the check at another instance with `DEVRADAR_OPENAPI_URL`.

## CI

On every push and pull request:

- [`qualify.yaml`](.github/workflows/qualify.yaml) — the reusable gate, three jobs:
  - **test** — format check, `go vet`, the race-detector suite with its coverage floor.
  - **lint** — golangci-lint, actionlint, yamllint, license headers, gitleaks
    (working tree *and* full history), and a check that `go mod tidy` is
    committed. Checks out at `fetch-depth: 0`, because a shallow clone makes the
    history secret scan pass without scanning anything.

    `.golangci.yaml` matches devproof's: ~25 linters including gosec,
    contextcheck, noctx, depguard, and `govet`'s shadow check.
  - **vuln** — `make vulncheck` (govulncheck at its pinned version).
  - **shell** — ShellCheck over `tools/`.
- [`test.yaml`](.github/workflows/test.yaml) — runs `qualify` on push/PR to `main`.

On a tag:

- [`release.yaml`](.github/workflows/release.yaml) — re-qualifies, resolves
  pinned tool versions, then calls the shared `thingzio/actions` build
  definition. See [RELEASING.md](RELEASING.md).

On a schedule:

- [`codeql.yaml`](.github/workflows/codeql.yaml) — CodeQL static analysis via
  the shared workflow, Mondays. Results land in the repository's security tab.
- [`verify-release.yaml`](.github/workflows/verify-release.yaml) — re-verifies
  the latest release's signature and provenance the way a consumer would,
  Mondays. devproof has a `keyless` workflow that signs a fixture against live
  Sigstore; devradarctl signs nothing, so the equivalent check is that what it
  *published* still verifies against the identity RELEASING.md names.

Supporting:

- [`load-versions`](.github/actions/load-versions/action.yaml) — composite
  action that turns `.versions.yaml` pins into step outputs.

Action SHAs are pinned; jobs use least-privilege `permissions` and
`persist-credentials: false`. Dependencies are not vendored — CI relies on the
Go module cache.

## Releasing

Releases are cut by pushing a semver tag (`make bump-patch`), which builds,
signs, attests, verifies, and only then publishes. The build reaches SLSA Build
Level 3 because the signing identity lives in a job that runs no code from this
repository.

The full procedure, the verification commands consumers should run, and what to
do when a release goes wrong are in **[RELEASING.md](RELEASING.md)**.
