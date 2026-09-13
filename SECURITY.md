# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/thingzio/devradarctl/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

Include, where you can: affected version or commit, a description of the
impact, and the smallest reproduction you have. A command line with its output,
an SBOM, an attestation bundle, or a captured request that triggers the behavior
is more useful than a description of it.

You should get an acknowledgement within three business days. We will tell you
whether we consider the report in scope, and keep you updated as a fix
progresses. Credit is offered by default in the advisory unless you ask
otherwise.

## Supported versions

Only the latest release receives fixes. There is no long-term support branch and
no backporting; a defect is addressed by cutting a new patch version.

## Scope

devradarctl is a client. It generates an SBOM for an image or reads one from
disk, resolves the image's manifest digest, and submits the result to a DevRadar
service over HTTPS with a bearer token. It does not host anything, and the
verification of attestations happens server-side — devradarctl transports the
bundle and reports the verdict.

That shape determines the boundary. The following are in scope for a report:

- disclosure of the API token or of registry credentials through process
  arguments, logs, error messages, temporary files, or a submitted payload;
- the API token reaching any host other than the configured `--base-url`,
  including through redirects;
- transport that does not authenticate the server, or any path that weakens or
  bypasses TLS verification;
- an SBOM submitted under a digest or image reference that does not identify the
  bytes it was actually generated from;
- reading or writing outside a path the invocation explicitly named;
- a CI gate that fails open — `--require-verified-attestation` exiting zero when
  verification did not return `verified`, or `findings --fail-on` exiting zero
  when the threshold it names is exceeded; and
- resource exhaustion that the documented payload limits should have bounded.

The following are **not** vulnerabilities in devradarctl:

- vulnerabilities, licenses, or malicious content in the images you scan.
  Reporting those is what the tool is for;
- cataloging accuracy of syft, which devradarctl invokes but does not
  reimplement. A package syft misses or misattributes is a syft issue;
- behavior of a registry, of the DevRadar service, or of syft that devradarctl
  correctly reported;
- a `--syft-path` or `DEVRADAR_SYFT_PATH` pointing at an untrusted binary.
  That value is operator-supplied configuration and names a program run with
  the caller's authority; it is inside the trust boundary, not outside it; and
- registry credentials held by the ambient Docker keychain. devradarctl reads
  the same credentials `docker pull` would and does not manage their storage.

## Security posture

- **The API token is never accepted as a command-line flag.** It comes from
  `DEVRADAR_TOKEN` or from piped stdin, because process arguments are readable
  by every other process on the host and land in shell history.
- SBOMs are generated against a **digest-pinned** reference, so the document
  identifies exact bytes rather than a tag someone can move.
- syft is executed with an explicit argument vector via `exec.CommandContext` —
  never through a shell, so no part of an image reference is interpreted.
- Payloads are size-limited before they are read into memory: 20 MiB for an
  SBOM, 10 MiB for an attestation bundle, 5 MiB for a VEX document.
- Every outbound request goes through a client with an explicit timeout, never
  `http.DefaultClient`.
- Releases are signed and carry SLSA Build Level 3 provenance. See
  [RELEASING.md](RELEASING.md) for how to verify a downloaded artifact.
