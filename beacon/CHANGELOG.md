# Beacon .NET Changelog

This file records Beacon .NET product changes only. See the root
[`CHANGELOG.md`](../CHANGELOG.md) for inherited upstream changes.

## Unreleased

- Add an opt-in Security runtime assembly inventory with periodic OTEL Logs
  publication and bounded multipart records. Add experimental ASP.NET Core query
  to file-read, SQL-template, HTTP-destination and process-invocation flow
  observations over OTEL Logs.
- Include experimental Security contract versions, the specification commit and
  schema/vector digests in artifact metadata, with the exact contracts bundled.
- Add separately opt-in Security diagnostic snapshots and an optional bounded
  JSONL finding file, without blocking request threads or changing OTLP export.

## 1.0.0 - 2026-09-28

- Publish the first stable Beacon .NET release.
- Provide one-command installation and complete uninstallation across supported
  Windows, Linux, and macOS environments.
- Include native MSI, DEB, and RPM packages alongside portable archives and
  standalone Shell and PowerShell installers.
- Verify downloadable artifacts with SHA-256 checksums, an SPDX SBOM, and
  GitHub artifact attestations.

## 0.2.2 - 2026-09-28

- Standardize Beacon product tags and GitHub Releases on the `vX.Y.Z` format.
- Update Shell and PowerShell installers, release workflows, and validation to
  use standard version tags without the former product-specific prefix.
- Isolate upstream-derived assembly and NuGet versioning from Beacon product
  tags so standard `vX.Y.Z` tags cannot lower runtime assembly versions.
- Refresh historical release links and make the latest release notes easier to
  scan.

## 0.2.1 - 2026-09-28

- Clear the build-time `ARCHITECTURE` override before the native Linux CLI
  starts an application, preventing an identically named host environment
  variable from interfering with runtime architecture detection.
- Use the dedicated `PACKAGE_ARCHITECTURE` variable in release and post-release
  validation workflows.

## 0.2.0 - 2026-09-28

- Add `uninstall.sh` to Linux/macOS installations and support
  `--uninstall` in the installer. Windows installations now generate
  `uninstall.ps1` to clean the current session, IIS, registered Windows
  Services, and core files in one operation.
- Add a Windows MSI, Linux DEB/RPM native packages, and the unified
  `beacon-dotnet status|version|run|uninstall` command.
- Make Windows Installer remove IIS, Windows Service, and GAC registrations
  before uninstalling files, preventing system configuration from referencing
  a removed profiler.

## 0.1.3 - 2026-09-25

- Fix the loss of the `instrument.sh` executable bit when artifacts move
  between GitHub Actions jobs.
- Make the Shell installer defensively restore the `instrument.sh` executable
  bit after extraction.

## 0.1.2 - 2026-09-24

- Require installation scripts to verify artifact attestations produced by the
  Beacon release workflow instead of depending on Immutable Releases, which
  must be enabled separately by a repository administrator.
- Use artifact attestations in post-release cross-platform download validation.

## 0.1.1 - 2026-09-24

- Add release archives for Linux glibc/musl x64 and ARM64, Windows, macOS, and
  NuGet.
- Add Shell and PowerShell installers plus post-release cross-platform
  installation and runtime validation.
- Add a unified SHA-256 manifest, an SPDX SBOM, and GitHub build attestations.
- Include Beacon version, target platform, and pinned upstream provenance
  metadata in every platform archive.

## 0.1.0 - 2026-09-24

- Establish a full-source downstream based on OpenTelemetry .NET Automatic
  Instrumentation `v1.17.0`.
- Add independent Beacon product versioning, provenance checks, and candidate
  archive packaging.
- Provide a Linux glibc x64 automatic-instrumentation archive validated with
  real-application OTLP traces, metrics, and logs.
- Add tag validation, artifact validation, and automated GitHub Release
  workflows.
