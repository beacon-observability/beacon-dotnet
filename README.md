# Beacon .NET

Beacon .NET is a .NET automatic-instrumentation distribution maintained as a
full-source downstream of OpenTelemetry .NET Automatic Instrumentation. This
repository is not a GitHub fork.

The project ships Linux glibc, Linux musl, Windows, macOS, and NuGet archives
for x64 and applicable ARM64 platforms, together with Windows MSI and Linux
DEB/RPM packages. Releases also include Shell and PowerShell installers,
checksums, an SPDX SBOM, and build attestations. After publication, the release
assets are downloaded again and used to run .NET 10 applications. End-to-end
DataKit ingestion is not currently within the verified support scope.

See the [Beacon development guide](beacon/README.md) for development, upstream
synchronization, artifacts, and release preparation. Inherited OpenTelemetry
usage and implementation documentation is available under
[OpenTelemetry .NET Automatic Instrumentation](docs/README.md).

## Runtime compatibility

This source update adopts upstream v1.20.0 and its .NET 10 / .NET 11 test
targets. Upstream removed the .NET 8 / .NET 9 targets; this candidate does not
claim continued support for those runtimes. CI covers the supported modern
runtimes and retains the existing Windows .NET Framework build path. A product
release requires separate compatibility review and cross-platform CI approval.

## Native Packages

Beacon provides a Windows MSI, Linux DEB/RPM packages, and the unified
`beacon-dotnet` command. Download the Release asset matching the host architecture
and install it:

```bash
# Debian / Ubuntu
sudo apt install ./beacon-dotnet-<version>-linux-amd64.deb

# RHEL / Rocky / Fedora
sudo dnf install ./beacon-dotnet-<version>-linux-x86_64.rpm
```

```powershell
# Run from an elevated Windows PowerShell session
Start-Process msiexec.exe -Wait -ArgumentList '/i beacon-dotnet-<version>-windows-x64.msi'
```

After installation, use the same commands on every supported platform:

```text
beacon-dotnet status
beacon-dotnet run <application-command> [arguments]
beacon-dotnet uninstall
```

Linux musl, macOS, containers, and non-administrator installations continue to
use the ZIP/Shell installation path.

## Uninstalling ZIP Installations

On Linux and macOS, run the uninstaller from the installation directory:

```sh
sh "$HOME/.otel-dotnet-auto/uninstall.sh"
```

On Windows, run the installation-directory uninstaller as an administrator:

```powershell
& "$env:ProgramFiles\OpenTelemetry .NET AutoInstrumentation\uninstall.ps1"
```

The Windows command cleans the current session and automatically detects and
removes IIS and Windows Service registrations that reference the current Beacon
installation. See the [usage documentation](docs/README.md#powershell-module-windows)
for detailed options.

## Beacon Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/lrwh"><img src="https://github.com/lrwh.png?size=80" width="80" height="80" alt="lrwh"><br><sub>lrwh</sub></a>
    </td>
  </tr>
</table>
