# devradarctl

CLI for the [DevRadar](https://devradar.thingz.io) service. It hides the
by-digest / all-layers / base64 mechanics of getting an SBOM into DevRadar behind
two commands:

- `devradarctl sbom` — generate an all-layers CycloneDX SBOM for a container image.
- `devradarctl submit` — submit an SBOM (from a file, or generated from an image).

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
  generate SBOMs. Only required for the `sbom` command and `submit --image`.
- Image digest resolution is done in-process (no `crane` needed) and uses your
  ambient Docker credentials (`docker login`, credential helpers).

## Usage

### Generate an SBOM

```sh
# Print to stdout
devradarctl sbom --image alpine:3.20

# Write to a file
devradarctl sbom --image alpine:3.20 --output alpine.cdx.json
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

## Configuration

| Flag             | Env var              | Default                       | Description                                   |
| ---------------- | -------------------- | ----------------------------- | --------------------------------------------- |
| `--base-url`     | `DEVRADAR_BASE_URL`  | `https://devradar.thingz.io`  | DevRadar service base URL                     |
| (token)          | `DEVRADAR_TOKEN`     | —                             | API token (or piped via stdin)               |
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
