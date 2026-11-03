#!/usr/bin/env bash

set -euo pipefail

check="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-generated-files.sh"
temporary="$(mktemp -d)"
trap 'rm -rf "${temporary}"' EXIT
cd "${temporary}"
git init --quiet
git config user.name 'Generated output test'
git config user.email 'generated-output@example.invalid'
output='src/OpenTelemetry.AutoInstrumentation/Generated/net8.0/System.Text.RegularExpressions.Generator/System.Text.RegularExpressions.Generator.RegexGenerator/RegexGenerator.g.cs'
mkdir -p "$(dirname "${output}")"
printf '%s\n' '[GeneratedCodeAttribute("System.Text.RegularExpressions.Generator", "8.0.14.42015")]' 'class Generated {}' > "${output}"
printf '%s\n' 'original' > other.g.cs
git add .
git commit --quiet -m 'Test baseline'
bash "${check}"
sed 's/8.0.14.42015/8.0.15.2219/' "${output}" > updated
mv updated "${output}"
bash "${check}"

expect_failure() {
  if bash "${check}" > /dev/null 2>&1; then
    echo "error: accepted $1" >&2
    exit 1
  fi
}

printf '%s\n' 'class Changed {}' >> "${output}"
expect_failure 'changed generated code'
git restore "${output}"
sed '1d' "${output}" > updated
mv updated "${output}"
expect_failure 'a removed provenance attribute'
git restore "${output}"
printf '%s\n' 'changed' > other.g.cs
expect_failure 'another changed file'
git restore other.g.cs
touch unexpected.g.cs
expect_failure 'an untracked generated file'
rm unexpected.g.cs
git rm --quiet "${output}"
expect_failure 'a deleted generated file'
echo 'Generated output checks passed'
