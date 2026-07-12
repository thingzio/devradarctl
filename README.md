# devradarctl

CLI for the [DevRadar](https://devradar.thingz.io) service. It hides the
by-digest / all-layers / base64 mechanics of getting an SBOM into DevRadar, and
wraps DevRadar's read API so you can inspect findings, images, licenses, and
change history — and gate CI on them — from the terminal.

| Command | Purpose |
| ------- | ------- |
| `sbom generate` | Generate an all-layers CycloneDX SBOM for a container image (local; `syft`). |
| `sbom get\|findings\|events\|failures\|licenses\|archive` | Inspect and manage a submitted SBOM. |
| `submit` | Submit an SBOM (from a file, or generated from an image). |
| `images list\|timeline\|sboms` | The tracked-image fleet view and per-image history. |
| `licenses` | Fleet-wide license rollup. |
| `vex submit\|list` | Submit and list OpenVEX documents. |
| `watch` | Poll for new change events until interrupted. |

> **Note:** local SBOM generation moved from `devradarctl sbom` to
> **`devradarctl sbom generate`** so `sbom` can host the read subcommands.

Read commands print a human-readable table by default; pass `--output json`
(`-o json`) for raw JSON to pipe into `jq`. In JSON mode every page is fetched;
tables show one page and hint when more exist (fetch all with `--all`).

## Install

Homebrew (macOS/Linux):

```sh
brew install thingzio/tap/devradarctl
```

With Go:

```sh
go install github.com/thingzio/devradarctl@latest
```

Or download a release archive from the [releases page](https://github.com/thingzio/devradarctl/releases).

### Prerequisites

- [`syft`](https://github.com/anchore/syft) on `PATH` (or pass `--syft-path`) — used to
  generate SBOMs. Only required for `sbom generate` and `submit --image`; the
  read/query commands need only a token.
- Image digest resolution is done in-process (no `crane` needed) and uses your
  ambient Docker credentials (`docker login`, credential helpers).

## Usage

### Generate an SBOM

```sh
# Print to stdout
devradarctl sbom generate --image alpine:3.20

# Write to a file
devradarctl sbom generate --image alpine:3.20 --output alpine.cdx.json
```

The image is pinned to its manifest digest (`repo@sha256:…`) before syft runs, so
the SBOM carries the digest DevRadar uses to identify the image unambiguously. The
SBOM is generated with **all layers** in scope by default (see `--scope`).

### Submit an SBOM

`submit` supports two modes. The API token is read from `DEVRADAR_TOKEN`, or
piped via stdin.

**Option 1 — from an image (recommended).** Point `devradarctl` at an image and
it does everything in one step: resolves the manifest digest, generates an
**all-layers** CycloneDX SBOM (the preferred form — it captures packages in
every layer, not just the final squashed filesystem), and submits it.

```sh
echo "$DEVRADAR_TOKEN" | devradarctl submit --image alpine:3.20 --label team-x --label prod
```

This requires [`syft`](https://github.com/anchore/syft) on `PATH`.

**Option 2 — from an existing SBOM file.** If your SBOM was already produced by
another process (a CI pipeline, an image-build step, etc.), submit it as-is —
no `syft` required. For the best inventory, generate that SBOM with all layers
in scope (e.g. `syft --scope all-layers`). Pass `--image-ref` so the submission
is pinned to the correct image digest.

```sh
DEVRADAR_TOKEN=xxx devradarctl submit --file alpine.cdx.json --image-ref alpine@sha256:…
```

**With a signed attestation (optional).** Pass `--attestation` with a
[sigstore](https://www.sigstore.dev/) bundle to have DevRadar cryptographically
verify the SBOM's subject against a signed provenance statement. Verification
happens **server-side** — the CLI only uploads the bundle; the DevRadar service
performs the check. When the service has a trust policy configured, the outcome
is reported as `attestation: verified` (or `failed`); a verification failure
never rejects the submission.

Any public image published with GitHub build provenance carries such a bundle.
Download it with the [`gh`](https://cli.github.com/) CLI, then submit — the
example below uses `ghcr.io/nvidia/aicr`, which publishes SLSA provenance:

```sh
# 1. Download the sigstore bundle for the image (writes <digest>.jsonl).
gh attestation download oci://ghcr.io/nvidia/aicr:v0.16.0 --repo NVIDIA/aicr

# 2. Submit the image and verify it against the downloaded bundle.
echo "$DEVRADAR_TOKEN" | devradarctl submit \
  --image ghcr.io/nvidia/aicr:v0.16.0 \
  --attestation sha256:223dcbeb0e3f3d9ccf4f92c9527ac466175181b1923f7535d1c65a68ef3cdffd.jsonl
```

The bundle also works in file mode alongside `--file`/`--image-ref`. For images
signed with `cosign`, `cosign download attestation <image>` produces an
equivalent bundle.

### Query & inspect

All read commands authenticate the same way as `submit` (`DEVRADAR_TOKEN` or
piped stdin) and accept `--output table|json` (`-o`).

```sh
# The fleet, risk-ranked (filter by repo substring / label).
devradarctl images list --min-severity high -q myrepo

# SBOMs and change history for one image.
devradarctl images sboms    --repo ghcr.io/acme/api
devradarctl images timeline --repo ghcr.io/acme/api

# Drill into one SBOM (id comes from `submit` or `images sboms`).
devradarctl sbom get      <sbom-id>
devradarctl sbom findings <sbom-id> --min-severity high --fixable
devradarctl sbom events   <sbom-id>
devradarctl sbom licenses <sbom-id>

# Fleet-wide license rollup; per-package detail lives under `sbom licenses`.
devradarctl licenses

# Pipe JSON into jq.
devradarctl sbom findings <sbom-id> -o json | jq '.[] | select(.kev)'

# Stop tracking an SBOM (prompts unless --yes).
devradarctl sbom archive <sbom-id>
```

### Gate CI on findings

`sbom findings --exit-code` exits non-zero (code **2**) when a threshold is
breached, so a pipeline step fails on unacceptable risk. Pair it with `--all`
(or `-o json`) so every page is considered.

```sh
# Fail the build if any critical/high vuln exists.
devradarctl sbom findings "$SBOM_ID" --all --exit-code --fail-on high

# Or cap counts per severity.
devradarctl sbom findings "$SBOM_ID" --all --exit-code --max-critical 0 --max-high 5
```

| Flag | Meaning |
| ---- | ------- |
| `--exit-code` | Exit non-zero when a threshold is breached. |
| `--fail-on <severity>` | Breach if any finding at or above this severity exists. |
| `--max-critical/-high/-medium N` | Breach if that severity's count exceeds `N`. |

### Watch for changes

`watch` polls on an interval and prints new change events as they appear, until
interrupted (Ctrl-C). Target one SBOM or one image across digests.

```sh
devradarctl watch <sbom-id>
devradarctl watch --repo ghcr.io/acme/api --interval 1m
```

### VEX assertions

Submit an [OpenVEX](https://github.com/openvex/spec) document to suppress
findings you've assessed as not affecting you, and list what you've submitted.

```sh
devradarctl vex submit statement.json
devradarctl vex list
```

**Scoping a statement's product.** DevRadar matches a VEX product two ways:

- **By digest** — `pkg:oci/<repo>@sha256:…` matches exactly one image and takes
  precedence. Use this for precision.
- **By repo** — `pkg:oci/<repo>` matches by image **name** (the last path
  segment) across digests, so a document written against `pkg:oci/aicr` still
  applies. Convenient, but broader.

VEX is a tenant assertion (unverified) and digest-scoped: a new image digest
needs a new statement unless you matched by repo.

### Shell completion

Completion is built in. For example, with bash:

```sh
source <(devradarctl completion bash)   # zsh|fish|powershell also supported
```

## Configuration

| Flag             | Env var              | Default                       | Description                                   |
| ---------------- | -------------------- | ----------------------------- | --------------------------------------------- |
| `--base-url`     | `DEVRADAR_BASE_URL`  | `https://devradar.thingz.io`  | DevRadar service base URL                     |
| (token)          | `DEVRADAR_TOKEN`     | —                             | API token (or piped via stdin)               |
| `--output`, `-o` | `DEVRADAR_OUTPUT`    | `table`                       | Read-command output format: `table`\|`json`   |
| `--label`        | `DEVRADAR_LABELS`    | —                             | Grouping label(s); repeatable                 |
| `--tag`          | —                    | image's tag                   | Image version to record (e.g. `v1.20.2`)      |
| `--image-ref`    | —                    | —                             | Digest-pinned image reference (file mode)     |
| `--attestation`  | —                    | —                             | Path to a sigstore/cosign bundle to verify    |
| `--syft-path`    | `DEVRADAR_SYFT_PATH` | `syft`                        | Path to the syft binary                       |
| `--scope`        | —                    | `all-layers`                  | syft cataloging scope                         |
| `--debug`        | `DEVRADAR_DEBUG`     | `false`                       | Debug logging (default level is warn)         |
| `--log-json`     | `DEVRADAR_LOG_JSON`  | `false`                       | Emit logs as JSON                             |

## Development

Contributing? See [DEVELOPMENT.md](DEVELOPMENT.md) for build, test, and release
instructions.

## License

MIT — see [LICENSE](LICENSE).
