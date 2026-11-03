#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
directory=""
target=""

fail() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  echo "usage: $0 --directory <path> --target <platform-id>" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory) [[ $# -ge 2 ]] || usage; directory="$2"; shift 2 ;;
    --target) [[ $# -ge 2 ]] || usage; target="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -n "${directory}" && -n "${target}" ]] || usage
[[ -d "${directory}" ]] || fail "directory does not exist: ${directory}"
[[ "${target}" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || fail "invalid target identifier: ${target}"

bash "${repository_root}/beacon/scripts/check-version.sh" >/dev/null
version="$(sed -n 's/^beacon\.version=//p' "${repository_root}/beacon/version.properties")"
upstream_repository="$(sed -n 's/.*"repository": "\([^"]*\)".*/\1/p' "${repository_root}/beacon/upstream.lock.json")"
upstream_tag="$(sed -n 's/.*"releaseTag": "\([^"]*\)".*/\1/p' "${repository_root}/beacon/upstream.lock.json")"
upstream_commit="$(sed -n 's/.*"releaseCommit": "\([0-9a-f]*\)".*/\1/p' "${repository_root}/beacon/upstream.lock.json")"
source_commit="$(git -C "${repository_root}" rev-parse HEAD)"
security_metadata="$(bash "${repository_root}/beacon/scripts/check-security-contract.sh")"

# Ship the exact contracts named by the provenance, not a floating remote link.
mkdir -p "${directory}/beacon-security"
cp "${repository_root}/beacon/security/spec.lock.json" \
  "${repository_root}/beacon/security/beacon-security-event-v2.schema.json" \
  "${repository_root}/beacon/security/fingerprint-v1.json" \
  "${directory}/beacon-security/"

cat > "${directory}/BEACON-METADATA.json" <<EOF
{
  "product": "Beacon .NET",
  "version": "${version}",
  "target": "${target}",
  "sourceCommit": "${source_commit}",
  "security": ${security_metadata},
  "upstream": {
    "repository": "${upstream_repository}",
    "releaseTag": "${upstream_tag}",
    "releaseCommit": "${upstream_commit}"
  }
}
EOF

echo "${directory}/BEACON-METADATA.json"
