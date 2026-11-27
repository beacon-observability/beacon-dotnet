#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
native_version="$(dotnet msbuild "${repository_root}/build/_build.csproj" -nologo -getProperty:MinVerVersionOverride)"
managed_version="$(dotnet msbuild "${repository_root}/src/OpenTelemetry.AutoInstrumentation/OpenTelemetry.AutoInstrumentation.csproj" -nologo -getProperty:MinVerVersionOverride)"

if [[ -z "${native_version}" || "${native_version}" != "${managed_version}" ]]; then
  echo "error: native build driver and managed profiler must use the same nonempty MinVer override" >&2
  echo "native=${native_version}; managed=${managed_version}" >&2
  exit 1
fi

echo "Native and managed upstream version: ${native_version}"
