#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$MsiPath,
    [scriptblock]$ValidateInstalled
)

$ErrorActionPreference = "Stop"
$msiPath = (Resolve-Path $MsiPath).Path
$installLog = Join-Path ([System.IO.Path]::GetTempPath()) "beacon-dotnet-msi-install-$([guid]::NewGuid().ToString('N')).log"
$install = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
    "/i", "`"$msiPath`"", "/qn", "/norestart", "/l*v", "`"$installLog`""
)
if ($install.ExitCode -notin @(0, 3010)) {
    Get-Content $installLog
    throw "MSI installation failed with exit code $($install.ExitCode)."
}

$installDirectory = [System.Environment]::GetEnvironmentVariable(
    "OTEL_DOTNET_AUTO_INSTALL_DIR",
    [System.EnvironmentVariableTarget]::Machine)
if (-not $installDirectory -or -not (Test-Path (Join-Path $installDirectory "BEACON-METADATA.json"))) {
    throw "MSI did not install Beacon metadata."
}

$cli = Join-Path $installDirectory "beacon-dotnet.ps1"
try {
    & $cli status
    if ($ValidateInstalled) {
        # Run checks before the CLI enables profiling in the current shell.
        & $ValidateInstalled $installDirectory
    }
    $env:OTEL_TRACES_EXPORTER = "none"
    $env:OTEL_METRICS_EXPORTER = "none"
    $env:OTEL_LOGS_EXPORTER = "none"
    & $cli run dotnet --info
    if (-not $?) {
        throw "beacon-dotnet run failed with exit code $LASTEXITCODE."
    }
}
finally {
    & $cli uninstall
}

if (Test-Path -LiteralPath $installDirectory) {
    throw "MSI installation directory still exists after uninstall."
}
if ([System.Environment]::GetEnvironmentVariable(
    "OTEL_DOTNET_AUTO_INSTALL_DIR",
    [System.EnvironmentVariableTarget]::Machine)) {
    throw "MSI installation locator still exists after uninstall."
}

Write-Output "MSI install, run, and uninstall checks passed."
