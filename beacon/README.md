# Beacon .NET Development Guide

This repository maintains the complete source tree of
[OpenTelemetry .NET Automatic Instrumentation](https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation)
and produces Beacon .NET artifacts from it. The product entry point is
[beacon-observability/beacon](https://github.com/beacon-observability/beacon).

## Current Status

- The downstream project is pinned to upstream `v1.17.0`, retains upstream
  history, and is maintained as a full-source repository rather than a GitHub
  fork.
- Beacon publishes Linux glibc/musl x64 and ARM64, Windows, macOS, and NuGet
  archives; Windows MSI and Linux DEB/RPM packages; and Shell and PowerShell
  installers.
- Native packages expose the cross-platform `beacon-dotnet` status, run, and
  uninstall commands. Their lifecycle is managed by the operating-system
  installer.
- Build jobs use real console and ASP.NET Core applications to verify OTLP
  traces, metrics, and logs. Post-release jobs download the public GitHub
  Release and run .NET 8 applications again.
- Releases include a unified SHA-256 manifest, an SPDX SBOM, and GitHub artifact
  attestations.
- An opt-in [Security runtime assembly inventory](security/README.md) is in
  development. Security finding detection and end-to-end DataKit ingestion are
  not yet within the verified support scope.

These statements describe the engineering readiness of Beacon itself. Upstream
support is not automatically treated as verified Beacon support.

## Repository Layout

| Location | Purpose |
| --- | --- |
| [`src`](../src/) | Managed automatic instrumentation, Startup Hook, Loader, and native CLR Profiler |
| [`nuget`](../nuget/) | Upstream-compatible NuGet package layout, published as an aggregate archive |
| [`build`](../build/) | Nuke build and test entry points |
| [`packaging`](../packaging/) | MSI, DEB/RPM, and installation-management commands |
| [`docs`](../docs/) | Inherited OpenTelemetry usage and implementation documentation |
| [`beacon`](./) | Beacon versioning, provenance, packaging, synchronization, and release documentation |

## Product and Artifact Boundaries

The public product name is **Beacon .NET**. Platform archives use this naming
scheme:

```text
beacon-dotnet-auto-<Beacon-version>-<platform-id>.zip
checksums.txt
```

Platform identifiers include `linux-glibc-x64`, `linux-musl-arm64`,
`macos-arm64`, and `windows-x64`. Archives retain the
`OpenTelemetry.AutoInstrumentation.*` assembly names, native-library names,
environment variables, and instrumentation-scope names. A repository-wide
brand-only rename would break compatibility with plugins, strong names, the CLR
Profiler, and the upstream ecosystem.

The aggregate NuGet archive retains upstream package IDs because the primary
package depends on companion BuildTasks, Loader, StartupHook, managed-runtime,
and native-runtime packages. Beacon will not publish a misleading
`Beacon.AutoInstrumentation` package until the complete package graph, naming,
dependencies, upgrades, and compatibility have been validated.

Native packages install into `/opt/beacon/dotnet` on Linux or
`%ProgramFiles%\Beacon\dotnet` on Windows and expose the `beacon-dotnet`
command. They reuse the same platform-archive contents rather than introducing
a second set of profiler binaries.

## Maintenance Entry Points

- [Pinned provenance and current baseline](upstream.lock.json)
- [Upstream synchronization process](UPSTREAM.md)
- [Product version](version.properties)
- [Artifacts and release preparation](RELEASING.md)
- [Beacon changelog](CHANGELOG.md)

Regular CI checks Beacon metadata and packaging scripts, builds Linux x64, and
uses the packaged archive to validate .NET 8 OTLP traces, metrics, logs, and
ASP.NET Core client/server automatic instrumentation. Tag workflows perform the
complete multi-platform build and first create a draft Release. Post-release
workflows then verify installers, artifact attestations, metadata, and real
application startup on Windows, macOS, and Linux glibc/musl.
