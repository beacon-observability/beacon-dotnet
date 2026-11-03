# Beacon .NET Release Preparation

Beacon .NET is distributed through versioned GitHub Releases. Every Release
must be rebuilt from a pinned commit by the tag workflow, created first as a
draft for manual verification, and downloaded again from the public Release for
post-publication validation.

## Versions and Tags

- [`version.properties`](version.properties) is the only manually maintained
  source for the Beacon product version.
- Development candidates use SemVer versions such as `0.2.0-alpha.1` and
  `0.2.0-rc.1`. Stable releases use `X.Y.Z`.
- Beacon product tags use the standard `v<version>` format. The upstream
  baseline tag remains in the repository for source provenance.
- [`Directory.Build.props`](../Directory.Build.props) isolates the
  upstream-derived assembly and NuGet version from product tags. Update
  `BeaconUpstreamDevelopmentVersion` whenever the upstream baseline advances.
- The Beacon product version is maintained independently of the upstream
  baseline in [`upstream.lock.json`](upstream.lock.json). Do not globally
  replace upstream assembly versions, NuGet dependencies, or instrumentation
  scope versions.

## Release Artifacts

Each release since `0.1.1` contains the following custom assets:

```text
beacon-dotnet-auto-<version>-linux-glibc-x64.zip
beacon-dotnet-auto-<version>-linux-glibc-arm64.zip
beacon-dotnet-auto-<version>-linux-musl-x64.zip
beacon-dotnet-auto-<version>-linux-musl-arm64.zip
beacon-dotnet-auto-<version>-windows.zip
beacon-dotnet-auto-<version>-macos.zip
beacon-dotnet-auto-<version>-nuget-packages.zip
beacon-dotnet-<version>-linux-amd64.deb
beacon-dotnet-<version>-linux-arm64.deb
beacon-dotnet-<version>-linux-x86_64.rpm
beacon-dotnet-<version>-linux-aarch64.rpm
beacon-dotnet-<version>-windows-x64.msi
otel-dotnet-auto-install.sh
OpenTelemetry.DotNet.Auto.psm1
checksums.txt
sbom.spdx.json
```

GitHub also provides source archives and Release attestations. Platform archives
retain upstream internal file names and include `BEACON-METADATA.json`, which
records the Beacon version, target platform, source commit, upstream tag, and
upstream commit. Its `security` object records experimental status, the disabled
default, schema/fingerprint versions, the pinned Security specification commit,
and schema/conformance-vector SHA-256 digests. The matching files are included in
`beacon-security/`. Metadata generation rejects missing, altered or unsupported
contracts before packaging. These declarations identify the implemented contract;
they do not establish platform acceptance or exploit detection. The aggregate
NuGet archive retains upstream-compatible package IDs.

DEB/RPM and MSI files must be covered by the unified checksum manifest and
artifact attestations. Windows Authenticode and APT/RPM repository signing are
not currently configured. Verify the GitHub artifact attestation before public
installation. Do not claim operating-system-native trust until official signing
identities have been provisioned.

To add metadata to an already-built directory and package it locally, run:

```bash
bash beacon/scripts/check-version.sh
bash beacon/scripts/package.sh \
  --input bin/tracer-home \
  --target linux-glibc-x64 \
  --output bin/beacon-artifacts
```

These scripts do not replace builds, unit tests, functional tests, or
platform-specific validation.

Metadata generation requires `jq` and either `sha256sum` or `shasum`. To check the
Security declarations and their rejection controls independently, run
`bash beacon/scripts/check-security-contract.test.sh`. The checked-in conformance
vectors deliberately include unpaired UTF-16 surrogates; their byte digest is
checked during packaging and their semantics are tested by the managed suite.

## Release and Acceptance Process

1. Pin the final source commit, upstream baseline, dependencies, and build
   environment. Confirm licenses and third-party notices.
2. Require the main-branch CI and the complete multi-platform release checks to
   pass.
3. Push a `v<version>` tag that matches `version.properties`.
4. The tag workflow builds every platform plus NuGet, MSI, and DEB/RPM assets;
   generates installers, checksums, an SBOM, and attestations; validates the
   archives; and creates a draft Release.
5. Manually inspect the draft file count, names, checksums, metadata, and release
   notes before publishing it.
6. The post-release workflow downloads the public Release, runs .NET 8
   applications on Windows, macOS, and Linux glibc/musl for x64 and ARM64, and
   verifies artifact attestations. MSI and DEB/RPM packages must also complete a
   real install-run-uninstall lifecycle.

Do not announce a release until every validation passes. Published tags and
assets are immutable; fix failures in code and increment the version. DataKit
ingestion requires independent end-to-end validation and must not be inferred
from OTLP export tests.
