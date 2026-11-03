#!/usr/bin/env bash

set -euo pipefail

# SDK patch versions can change this generator's provenance stamp without
# changing its output. Keep every other generated-code difference actionable.
regex_output='src/OpenTelemetry.AutoInstrumentation/Generated/net8.0/System.Text.RegularExpressions.Generator/System.Text.RegularExpressions.Generator.RegexGenerator/RegexGenerator.g.cs'
normalize_stamp='s/^([[:space:]]*\[(global::System\.CodeDom\.Compiler\.)?GeneratedCodeAttribute\("System\.Text\.RegularExpressions\.Generator", ")[0-9]+(\.[0-9]+)+("\)\][[:space:]]*)$/\1SDK_VERSION\4/'

git diff --exit-code HEAD -- . ":(exclude)${regex_output}"
baseline="$(git show "HEAD:${regex_output}" | sed -E "${normalize_stamp}" | git hash-object --path="${regex_output}" --stdin)"
actual="$(sed -E "${normalize_stamp}" "${regex_output}" | git hash-object --path="${regex_output}" --stdin)"
if [[ "${baseline}" != "${actual}" || -n "$(git diff --summary HEAD -- "${regex_output}")" ]]; then
  echo 'error: generated regex code changed beyond the SDK version stamp' >&2
  git diff HEAD -- "${regex_output}" >&2
  exit 1
fi
if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo 'error: generation left untracked files' >&2
  git ls-files --others --exclude-standard >&2
  exit 1
fi
