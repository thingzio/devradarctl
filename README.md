# devradarctl

CLI for the [DevRadar](https://github.com/thingzio/devradar) service. It hides the
by-digest / all-layers / base64 mechanics of getting an SBOM into DevRadar behind
two commands:

- `devradarctl sbom` — generate an all-layers CycloneDX SBOM for a container image.
- `devradarctl submit` — submit an SBOM (from a file, or generated from an image).

## Install

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
the SBOM carries the digest DevRadar uses to identify the image unambiguously.

### Submit an SBOM

The API token is read from `DEVRADAR_TOKEN`, or piped via stdin.

```sh
# From an existing SBOM file
DEVRADAR_TOKEN=xxx devradarctl submit --file alpine.cdx.json --image-ref alpine@sha256:…

# From an image (resolve digest, generate, submit — one step)
echo "$DEVRADAR_TOKEN" | devradarctl submit --image alpine:3.20 --group team-x --group prod
```

## Configuration

| Flag             | Env var              | Default                       | Description                                   |
| ---------------- | -------------------- | ----------------------------- | --------------------------------------------- |
| `--base-url`     | `DEVRADAR_BASE_URL`  | `https://devradar.thingz.io`  | DevRadar service base URL                     |
| (token)          | `DEVRADAR_TOKEN`     | —                             | API token (or piped via stdin)               |
| `--group`        | `DEVRADAR_TAGS`      | —                             | Grouping label(s); repeatable / comma env     |
| `--syft-path`    | `DEVRADAR_SYFT_PATH` | `syft`                        | Path to the syft binary                       |
| `--scope`        | —                    | `all-layers`                  | syft cataloging scope                         |
| `--debug`        | `DEVRADAR_DEBUG`     | `false`                       | Debug logging (default level is warn)         |
| `--log-json`     | `DEVRADAR_LOG_JSON`  | `false`                       | Emit logs as JSON                             |

## Development

Contributing? See [DEVELOPMENT.md](DEVELOPMENT.md) for build, test, and release
instructions.

## License

MIT — see [LICENSE](LICENSE).
