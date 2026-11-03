#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_directory="${repository_root}/beacon/security"
if [[ $# -ne 0 ]]; then
  [[ $# -eq 2 && "$1" == "--directory" ]] || { echo "usage: $0 [--directory <contract-directory>]" >&2; exit 2; }
  contract_directory="$2"
fi

fail() {
  echo "error: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required to validate Security provenance"
lock="${contract_directory}/spec.lock.json"
schema="${contract_directory}/beacon-security-event-v2.schema.json"
vectors="${contract_directory}/fingerprint-v1.json"
[[ -f "${lock}" && -f "${schema}" && -f "${vectors}" ]] || fail "Security contract files are missing"

# Reject unsupported declarations rather than stamping a new version onto an old runtime.
jq -se '
  length == 1 and (.[0] |
  type == "object" and
  .repository == "https://github.com/beacon-observability/beacon-security-spec" and
  (.commit | type == "string" and test("^[0-9a-f]{40}$")) and
  .target_schema_version == 2 and .fingerprint_version == 1 and
  (.event_schema_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
  (.fingerprint_vectors_sha256 | type == "string" and test("^[0-9a-f]{64}$")))
' "${lock}" >/dev/null || fail "invalid or unsupported Security contract lock"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum < "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 < "$1" | cut -d ' ' -f 1
  else
    fail "sha256sum or shasum is required to validate Security provenance"
  fi
}

[[ "$(hash_file "${schema}")" == "$(jq -r '.event_schema_sha256' "${lock}")" ]] || fail "Security event schema digest does not match the lock"
[[ "$(hash_file "${vectors}")" == "$(jq -r '.fingerprint_vectors_sha256' "${lock}")" ]] || fail "Security fingerprint vectors digest does not match the lock"
jq -e '."$defs".inventory.properties.schema_version.const == 2 and ."$defs".finding.properties.schema_version.const == 2 and ."$defs".finding.properties.fingerprint_version.const == 1' "${schema}" >/dev/null || fail "Security schema version declarations do not match the runtime"
# The normative vectors deliberately contain unpaired UTF-16 surrogates, which
# jq rejects. Preserve their bytes here; managed conformance tests interpret them.

# Stdout is machine-readable so packaging can embed the validated declaration.
jq -c '{
  status: "experimental",
  enabledByDefault: false,
  schemaVersion: .target_schema_version,
  fingerprintVersion: .fingerprint_version,
  spec: {
    repository: .repository,
    commit: .commit,
    schemaSha256: .event_schema_sha256,
    fingerprintVectorsSha256: .fingerprint_vectors_sha256
  }
}' "${lock}"
