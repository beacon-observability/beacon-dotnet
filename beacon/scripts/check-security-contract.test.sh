#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_root="$(mktemp -d "${TMPDIR:-/tmp}/beacon-security-contract-test.XXXXXX")"
trap 'rm -rf -- "${test_root}"' EXIT
check="${repository_root}/beacon/scripts/check-security-contract.sh"

reset_fixture() {
  cp "${repository_root}/beacon/security/"*.json "${test_root}/"
}

expect_rejected() {
  if bash "${check}" --directory "${test_root}" >"${test_root}/output" 2>"${test_root}/error"; then
    echo "error: invalid Security contract accepted: $1" >&2
    exit 1
  fi
  [[ ! -s "${test_root}/output" ]]
}

reset_fixture
bash "${check}" --directory "${test_root}" | jq -e \
  '.schemaVersion == 2 and .fingerprintVersion == 1 and .enabledByDefault == false and .status == "experimental"' >/dev/null

printf '\n' >> "${test_root}/beacon-security-event-v2.schema.json"
expect_rejected "modified schema"
reset_fixture
printf '\n' >> "${test_root}/fingerprint-v1.json"
expect_rejected "modified conformance vectors"

for update in \
  '.target_schema_version = 3' \
  '.fingerprint_version = 2' \
  '.commit = "main"' \
  '.repository = "https://example.invalid/spec"' \
  '.event_schema_sha256 = "invalid"' \
  'del(.fingerprint_vectors_sha256)'; do
  reset_fixture
  jq "${update}" "${test_root}/spec.lock.json" > "${test_root}/modified.json"
  mv "${test_root}/modified.json" "${test_root}/spec.lock.json"
  expect_rejected "${update}"
done

reset_fixture
cat "${test_root}/spec.lock.json" "${test_root}/spec.lock.json" > "${test_root}/multiple.json"
mv "${test_root}/multiple.json" "${test_root}/spec.lock.json"
expect_rejected "multiple lock documents"

reset_fixture
rm "${test_root}/fingerprint-v1.json"
expect_rejected "missing conformance vectors"

# Exercise Windows-style checkout conversion without touching the user's index.
security_test_index="${test_root}/checkout.index"
security_test_checkout="${test_root}/checkout"
mkdir -p "${security_test_checkout}"
GIT_INDEX_FILE="${security_test_index}" git -C "${repository_root}" read-tree --empty
GIT_INDEX_FILE="${security_test_index}" git -C "${repository_root}" add -- \
  .gitattributes beacon/security/spec.lock.json \
  beacon/security/beacon-security-event-v2.schema.json beacon/security/fingerprint-v1.json
security_test_control="$(printf 'control\n' | git -C "${repository_root}" hash-object -w --stdin)"
GIT_INDEX_FILE="${security_test_index}" git -C "${repository_root}" update-index --add \
  --cacheinfo "100644,${security_test_control},beacon/security-checkout-control.txt"
GIT_INDEX_FILE="${security_test_index}" git -C "${repository_root}" -c core.autocrlf=true \
  checkout-index --all --prefix="${security_test_checkout}/"
[[ "$(cat "${security_test_checkout}/beacon/security-checkout-control.txt")" == $'control\r' ]]
bash "${check}" --directory "${security_test_checkout}/beacon/security" >/dev/null

echo "Security contract tests passed"
