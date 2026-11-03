# Beacon Security for .NET (in development)

<!-- cspell:words Pkcs -->

The shared contract is pinned in [spec.lock.json](spec.lock.json). The target
wire format is schema 2 with fingerprint version 1. This directory does not
declare runtime support or release acceptance.

## Implementation and acceptance

- Finding identity: internal SHA-256 implementation and the complete pinned
  fingerprint conformance vectors are included in the managed unit tests.
- Runtime lifecycle: opt-in asynchronous SBOM collection and cancellable serial
  refresh are implemented. Security defaults to off; SBOM defaults to on within
  an enabled Security lifecycle. Local diagnostic snapshots are separately opt-in
  and use a bounded asynchronous writer.
- Request tracking: the request-local object identity and concatenation range
  model is implemented and unit tested. CallTarget concatenation callbacks,
  ambient request scopes and an independent Security definition gate are present.
  Native CoreCLR concat activation is implemented and locally exercised on Linux
  x64/.NET 8, .NET 9 and .NET 10. ASP.NET Core request scopes and query sources
  bind to the asynchronous hosting pipeline. File-read, ADO.NET text-command,
  asynchronous HTTP destination and process-start callbacks are connected.
  Raw request values, SQL and shell scripts never enter event fields.
- Findings: request-local fingerprint deduplication, distinct occurrence IDs and
  evidence upgrades, bounded wire records and schema-2 OTEL Logs emission are
  implemented. File-read flows retain unknown attack evidence because no allowed
  path-boundary policy is available. Broader sink coverage and classifiers remain
  pending. A modeled flow is not a confirmed exploit.
- Runtime SBOM: loaded CLR assembly identities, periodic serial publication,
  process timing and multipart byte-budget handling are implemented. NuGet package
  mapping, artifact hashes and local CycloneDX files are not implemented.
- Acceptance: local Linux x64/.NET 8, .NET 9 and .NET 10 disabled-mode, concurrent
  HTTP, file-read flow and OTLP checks pass, alongside schema validation.
  Narrow [performance measurements](PERFORMANCE.md) are recorded. Broad rule
  coverage, production performance, further failure/shutdown and platform
  validation remain pending.

Fingerprint tests cover language-neutral inputs; passing those tests alone is
not evidence of .NET source-to-sink detection or backend delivery.

## Current runtime binding

| Environment variable | Default | Behavior |
| --- | --- | --- |
| `BEACON_SECURITY_ENABLED` | `false` | Enable the Security lifecycle. |
| `BEACON_SECURITY_SBOM_ENABLED` | `true` | Collect loaded assemblies while Security is enabled. |
| `BEACON_SECURITY_SBOM_REFRESH_SECONDS` | `300` | Positive integer delay after each completed collection; invalid values use 300. |
| `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED` | `false` | Enable process-local diagnostic snapshots and the optional evidence file. |
| `BEACON_SECURITY_OUTPUT` | System temporary directory / `beacon-security` | Snapshot root; each process uses its instance UUID as a subdirectory. |
| `BEACON_SECURITY_EVIDENCE_FILE` | unset | Optional JSONL finding evidence file; ignored unless local output is enabled. |

Only environment-variable bindings are currently implemented. This does not add
App.config or YAML bindings. Transport and resource identity reuse the existing
OTEL Logs provider and `OTEL_EXPORTER_OTLP_*`, `OTEL_LOGS_EXPORTER`, and
`OTEL_RESOURCE_ATTRIBUTES` configuration. Disabling automatic logs prevents SBOM
and finding export through OTEL Logs. Separately enabled local output can still
receive inventory and findings with automatic logs disabled. Disabling automatic
SDK setup prevents both the Security worker and local writer from starting.
Security does not enable log4net or NLog instrumentation.

The initial collection runs on a worker. Collections observe at most 4096 unique
loaded, non-dynamic assembly name/version pairs; capacity or scan failures publish
no replacement. Versions are CLR assembly versions, not NuGet package versions.
Records are bounded to 65536 UTF-8 bytes, including multipart metadata. If an entry
cannot be encoded or fit, the entire round fails. SDK transport remains best effort.

Process start time comes from `Process.StartTime`. Initial uptime is estimated
from that timestamp, then advances using `Stopwatch` rather than subsequent wall
clock differences. Collection timestamps strictly increase within the producer.
Shutdown cancels pending delays and prevents further emission, without waiting for
an in-progress scan. Cross-AppDomain identity and platform acceptance remain open.

## Local validation

The taint model uses weak string identity keys and exact UTF-16 concatenation
ranges. Equal content in a different string does not establish flow. Per-request
limits are 64 source observations, 1024 source/propagation operations, and 128
ranges per propagated object. Budget exhaustion marks collection incomplete;
closing a request prevents further tracking and observation. Deduplication holds
up to 128 findings per request, with evidence ordered suspected, unknown, then
no evidence. ASP.NET Core query values are automatically tagged by identity at
request entry, with a maximum of 64 values. The completion callback closes the
scope on success or exception. No request body is read by this adapter. Headers,
cookies, route values, forms and other source frameworks are not modeled yet.
The current sink observes tainted paths passed to `File.ReadAllText(string)`,
including failed invocations. It reports `path_traversal` candidate flow with
`attack_evidence.status=unknown` and reason `path_boundary_policy_unavailable`.
It does not assess whether the path escapes an allowed directory. Other file APIs
are not covered yet. Findings are deduplicated within a request and exported on
completion. Records are limited to 65536 UTF-8 bytes;
optional source/range evidence can be omitted with explicit truncation flags.
If the identifying envelope still cannot fit, the record is dropped. There are
no replacement diagnostic or replay events.

CoreCLR retains its core-library module for explicit ReJIT definitions only when
Security is enabled. Before registering concat definitions, managed code warms
the applicable CallTarget delegates and integration options, and executes their
entry paths to resolve lazy `Activity.Current` dependencies. Registration fails
closed if that preparation fails. Without this preparation, the isolated native
experiment exposed recursive concat calls during delegate initialization and a
startup crash. Prewarming removed that failure in the Linux x64/.NET 8 smoke run:
an actual `String.Concat` returned one tainted range for a manually tagged source;
the disabled control returned zero. This validates propagation plumbing, not HTTP
source-to-sink detection. .NET Framework's shared-AppDomain core-library path is
unchanged and not validated. Other framework exclusions remain intact.

`SmokeTests.SecurityConcatPropagationWithoutTelemetryInstrumentation` covers
enabled and disabled processes with traces, metrics and logs disabled. It invokes
the 2-, 3- and 4-string concat overloads against a manually tagged source. Both
cases passed locally with the rebuilt Linux x64 profiler on .NET 8. The 65 managed
Security tests also passed. Run the native smoke cases after building the profiler
and `TestApplication.Smoke` into the normal integration-test layout:

```sh
dotnet test test/IntegrationTests -f net8.0 -p:Platform=x64 --filter FullyQualifiedName~SecurityConcatPropagationWithoutTelemetryInstrumentation
```

`MinimalApiTests.SecurityQuerySourcesFlowThroughAsyncConcurrentRequests` exercises
automatic query capture with concurrent HTTP requests, an asynchronous handler,
and a real concat call, without manually tagging a source. Enabled/disabled
controls run with telemetry instrumentation disabled and verify separate scopes
for the two requests. Both HTTP controls and both concat controls passed locally
on Linux x64/.NET 8 (four integration cases). Separate unit tests cover source
capacity and completion cleanup when the application throws.

The managed Security tests cover pinned fingerprint vectors, inventory capacity,
UTF-8 byte budgets, multipart completeness, configuration defaults, cancellation,
failed scans and SDK log dispatch. Run them with:

```sh
dotnet test test/OpenTelemetry.AutoInstrumentation.Tests -f net8.0 --filter FullyQualifiedName~Tests.Security
```

Early local checks used `-p:NuGetAudit=false` while the build/test cryptography
dependency baseline failed audit. The separate prerequisite fixes described below
now permit audit-enabled validation. Earlier audit-disabled results and benchmark
reports are retained as historical evidence. Generated inventory parts also pass
the pinned schema v2, including RFC 3339 timestamps. Schema validation alone does
not establish Collector or backend receipt.

`MinimalApiTests.SecurityFileFindingsReachOtlpWithoutRequestValues` verifies the
first automatic source-to-sink/export path. Each of two concurrent HTTP requests
attempts the same tainted file read twice. The enabled control receives two OTLP
findings with one stable finding ID, distinct occurrence IDs and no request values;
the disabled control receives none. The seven file/query/concat integration cases
pass on Linux x64/.NET 8; additional SQL and HTTP cases are described below. This
is local collector receipt, not DataKit/backend acceptance.

The pinned schema is included beside this guide. To repeat JSONL wire validation
with Python and the `jsonschema` development dependency installed:

```sh
python3 beacon/scripts/validate-security-events.py events.jsonl
```

Full and byte-compacted findings plus multipart inventories were validated with
this script. It rejects empty files and schema violations without printing input
payloads. This validator is not loaded by the runtime.

Findings retain available request method, endpoint route template, response status
and non-empty error type. The adapter inspects up to 128 features to locate the
endpoint. It never substitutes the raw request path or query string for a missing
route. An exception before response headers start omits the default status rather
than implying a successful 200 response. Exception messages are not collected.
The completion callback clears its HTTP context provider when closing the scope.

W3C trace context is captured at the sensitive invocation, independently of later
span completion. The closest in-process server ancestor supplies `server_span_id`;
`current_span_id` is omitted when equal to that server span. Native OTEL log
correlation retains the captured current span, including when export happens
later. Legacy hierarchical IDs are omitted. Correlation does not establish that a
backend retained the corresponding trace. The enabled-tracing collector case
verifies that JSON and native OTLP IDs agree; unit tests cover distinct child
spans and exception/status handling. Schema checks cover context preservation in
both full and byte-compacted records.

## SQL observations (in development)

ADO.NET execute-reader, scalar and non-query callback families (sync and async)
carry independent Security registrations. They reuse the same callback classes as
tracing, so a method is not assigned competing implementations. Tracing-disabled
Security calls do not create ADO.NET spans. A request-local SQL scope suppresses
nested callbacks for the same command and releases command references on completion.
Provider metadata failures mark the request collection incomplete; recursive
metadata inspection is guarded.

Only `CommandType.Text` templates with retained string-identity taint produce
`sql_injection` observations. Parameter values do not taint a constant template.
Calling `Prepare()` does not clear a previously concatenated template's taint.
Attack evidence remains `unknown` with `sql_dialect_analysis_unavailable`; this
implementation does not parse dialect-specific attack syntax or establish exploit
success. An absent observation is not a general safety verdict, especially for
transformations outside the model or providers that replace the template string object.

Runtime acceptance currently uses Microsoft.Data.Sqlite 10.0.12, an in-memory
database and ASP.NET Core query sources on Linux x64/.NET 8. Seven SQL integration
cases cover disabled mode, tracing on/off, sync/async scalar APIs, preparation,
parameter binding and request/nested-call deduplication. Tracing-enabled cases
also check four ADO.NET spans for four executions and the native finding span
correlation. Other providers, full execute-method/version matrices and .NET
Framework need separate runtime acceptance. The original seven Security cases
remain in the regression suite.

## HTTP destination observations (in development)

The asynchronous `System.Net.Http.HttpMessageInvoker.SendAsync` entry observes
HttpClient APIs that pass through it, including `GetStringAsync`. Absolute HTTP
and HTTPS URIs are matched using `Uri.OriginalString` object identity. Equal
content alone does not establish propagation. Relative-address merging, URI
reconstruction, synchronous send APIs and custom handler/redirect behavior need
additional coverage; an absent finding is not a safety verdict.

Retained ranges intersecting the original scheme/authority select `ssrf` and
`destination_address`. Path/query-only ranges select `http_request_input`, with
`input_part` set to path, query or both. Fragment-only ranges are not reported as
HTTP input. These classifications describe modeled flow boundaries, not validated
network trust: no DNS resolution, destination allowlist, proxy/rebinding analysis,
redirect validation or exploit confirmation is performed. Attack evidence stays
`unknown`. Raw URIs, host names, ports and query values do not enter finding fields.

Eight loopback-only HTTP integration cases verify enabled/disabled behavior,
tracing, constant destinations, path/query inputs, fragment exclusion, per-request
deduplication and collector privacy. URI identity and boundary behavior also have
unit coverage. Full and compact address/query/path findings pass the pinned schema
validator. Including the process cases below, the combined native suite passes 29
cases on Linux x64/.NET 8, alongside 65 managed Security tests. The full selection
also passes on .NET 10 as detailed below. Other runtimes and platforms remain
not validated.

## Process invocation observations (in development)

The CoreCLR `Process.Start()` instance entry observes executable names, the
`Arguments` string and up to 128 `ArgumentList` entries by retained identity.
Excess list entries mark collection incomplete. Ordinary executable/argument
flows produce `command_execution`; shell syntax characters alone do not turn an
argument into a shell script. Common shell file names with a first command option
(`-c`, `-lc`, `/c`, or `-Command`) identify modeled `command_injection` script flows.
This is not a shell parser, executable authenticity check or exploit assessment.
Evidence stays `unknown`, and `UseShellExecute` is not treated as proof of shell
interpretation. Command lines, scripts, executable paths and environment values
are never exported as finding fields.

The native profiler makes a Security-only exception for exactly
`System.Diagnostics.Process` in module/reference filtering. All other diagnostics
prefix exclusions and the disabled default remain unchanged. No process launch,
arguments, environment, return value or exception is modified by the observer.

Seven integration cases use fixed `/bin/echo` and guarded `printf` inputs on
Linux, or fixed Windows system commands, plus a nonexistent executable. They
cover disabled/constant controls,
argument versus shell-script roles, tracing, deduplication and failed invocation
attempts. The fixture permits only two fixed values before constructing a shell
script. Shell file names use case-insensitive comparison on Windows and exact
comparison on Unix. Metadata-only schema checks start no processes and cover
executable,
argument and script roles in full/compacted records. Windows dispatch, arbitrary
shell options/grammars, wrappers and broader version matrices remain not validated.

## Runtime inventory delivery checks

Four additional `SmokeTests.SecurityInventoryRefreshReachesOtlp` cases pass on
Linux x64/.NET 8. With Security enabled and the SBOM default retained, a real
application delivers two complete inventory rounds through the normal OTLP Logs
exporter at a one-second test interval. They retain the same instance/start time,
advance collection time and uptime, and include the loaded application assembly.
Separate controls disable Security, SBOM or automatic logs and receive no records.
The probe exits before normal smoke traffic and does not make external requests.

The positive probe is terminated after collector receipt; it does not establish
graceful application shutdown. Managed lifecycle tests separately verify recovery
after a failed scan, cancellation of pending delays and suppression of publication
when disposal occurs during a scan. Multipart encoding has managed/schema coverage;
collector acceptance of large multipart inventories remains not validated. These
four delivery cases bring the locally exercised integration total to 33.

## Artifact contract provenance

`BEACON-METADATA.json` declares the implemented schema/fingerprint versions and
the immutable specification commit under `security`, alongside experimental
status and the disabled default. Artifact metadata generation validates the lock,
schema and fingerprint-vector byte digests and rejects unsupported versions.
Platform archives include these exact files in `beacon-security/`; the vectors
also supply the managed conformance tests directly from this directory.

The package tests verify both metadata and extracted contract files. Release
archive validation repeats the contract checks after extraction. This records
contract identity, not platform acceptance, backend delivery or vulnerability
confirmation. See [release instructions](../RELEASING.md) for tooling requirements.

A local Linux x64 candidate made from the rebuilt native profiler and managed
producer was packaged, extracted and used to rerun all 33 Security integration
cases successfully on .NET 8. This checks behavior from the packaged payload,
including periodic inventory delivery. The CI candidate validation is configured
to build the MinimalApi fixture and run the same Security test selection after
unpacking; a remote CI/release run has not been performed for these changes.

The managed producer also cross-compiles for .NET Framework 4.6.2 with zero
warnings/errors using the pinned reference-assembly packages. On Linux, the local
check used `-p:OS=Windows_NT` to select the repository's existing Windows target
framework list, preserving the generator's `netstandard2.0` target. This is a
compile check only; Framework runtime/profiler and Windows behavior remain
not validated. NuGet audit was disabled for the known dependency baseline noted
above.

## Local diagnostic snapshots

Security and local output must both be enabled before creating a diagnostic
writer. Setting either output path alone does not enable disk output. The writer
creates directories only when it receives a record. `inventory.jsonl` contains
the complete latest accepted collection, including every multipart record;
`finding.json` contains the latest accepted finding. Temporary files are replaced
within the process directory, so a rejected or failed collection does not publish
a partial inventory snapshot. These files use the same schema-2 bodies as OTLP,
without adding raw request values, SQL, command lines or scripts. They are not
CycloneDX documents.

File I/O runs on a single background worker. At most 64 pending work items and
4 MiB of UTF-8 payload (including an in-flight item) are retained; an oversized
inventory round is rejected as a whole. Capacity exhaustion drops diagnostic
work without blocking application requests or retaining a replay backlog. The
optional evidence file contains only finding JSONL, with an 8 MiB current file
and one `.1` previous file. Use a distinct evidence path per process: these files
do not provide multi-process aggregation or backend delivery evidence. Existing
process directories are not automatically deleted.

The first filesystem error stops that process's local writer and discards its
pending diagnostic work. OTLP export continues independently. Shutdown stops new
enqueue operations and allows queued work to drain asynchronously; process exit
does not wait for a blocked filesystem and can lose pending local writes. Local
snapshots do not confirm backend receipt and are not a durable event history.

Five Linux x64/.NET 8 integration controls verify local-only delivery with logs
disabled, Security/local-output opt-in gates, simultaneous local/OTLP delivery,
and continued OTLP delivery when the snapshot directory is unusable. They check
shared inventory/finding instance IDs, distinct request occurrences and absence
of request values in local event fields. The fixture explicitly drains its
diagnostic writer; this does not establish graceful-exit delivery guarantees.
Managed tests cover byte budgets, in-flight accounting, complete-round snapshot
replacement, bounded evidence rotation and destination failure without retries.
A separate real-application run produced four local records (inventory, finding
snapshot and two JSONL occurrences), all passing the pinned schema v2 validator.
The combined Security integration selection now passes 38 cases, alongside 65
managed Security tests. The updated producer also cross-compiles for net462 with
zero warnings/errors; Framework runtime behavior remains not validated.

## Additional runtime checks

| Check on Linux x64 | .NET 8 | .NET 9 | .NET 10 |
| --- | --- | --- | --- |
| Focused Security unit tests | 65 passed | 65 passed | 65 passed |
| Security integration tests, audit enabled | 38 passed | 38 passed | 38 passed |
| Complete core managed suite, audit enabled | 827 passed | 827 passed | 829 passed, 2 platform skips |

Native `net9.0` and `net10.0` Smoke and MinimalApi fixtures and test harnesses run
on Microsoft.NETCore.App/Microsoft.AspNetCore.App 9.0.22 and 10.0.14 respectively.
All 65 managed Security tests and all 38 Security integration cases pass on each
runtime on Linux x64. These are native TFM runs, not .NET 8 applications rolled
forward to another runtime. They cover disabled controls, concat propagation,
concurrent request scope,
file/SQL/HTTP/process flows, local-only output, destination failure and periodic
inventory delivery. CI is configured to repeat .NET 9/.NET 10 checks against the
packaged candidate; that remote CI run has not been performed locally.

.NET Framework runtime behavior, Windows, macOS and other architectures have not
been validated. The local .NET 8/.NET 10 performance reports describe only a
single-client, failing-file workload; they do not establish a production overhead
budget.

The complete core managed unit suite passes 827 tests on .NET 8 and .NET 9, and
829 tests on .NET 10 with two Windows-only checks skipped. These runs use normal
audit-enabled restore/build settings and a consistent task SDK for child CLI
commands. Both previously failing `FrameworkDistroTests` checks pass in the latest
complete .NET 10 run. Their assertions and 20-second child-command limit were not
changed. This does not prove that the dependency change alone caused the earlier
timing failures to disappear.

## Cryptography audit prerequisite

An independent local `fix/pkcs-build-audit` branch contains the prerequisite
dependency commits. The feature branch includes their equivalents separately
from the Security implementation. They pin build-tool PKCS to 8.0.2,
and test PKCS plus shared build/test XML cryptography to 10.0.13, using the first
patched versions identified by the Microsoft
[PKCS](https://github.com/advisories/GHSA-846f-f764-76mx) and
[XML](https://github.com/advisories/GHSA-7hqp-7c5m-4vq6) advisories. The integration-test
host explicitly overrides vulnerable PKCS versions inherited from SQL client.
No advisory suppression or reduced audit settings were added.

Audit-enabled restores pass for Nuke, the core test project, the integration-test
host, WCF client and distribution project. Default .NET 10 and legacy .NET 9 Nuke
builds pass, as does the WCF client build. Comparing resolved package names and
versions for all seven distribution targets (`net8.0`, `net9.0`, `net10.0`,
`net462`, `net47`, `net471`, `net472`) finds no changes. The source distribution's
excluded XML override remains 4.7.1. Package assets retain .NET Framework 4.6.2
support. No dependency commit has been pushed or submitted for review.

The Security managed project also compiles for `net462` with audit enabled and
zero warnings/errors, using the Windows reference-assembly restore on Linux.
This compilation does not validate .NET Framework runtime behavior.

The solution-based `dotnet format --verify-no-changes --no-restore` check passes
with the 57 changed C# files selected by `--include`; generated files are excluded.
Whitespace checks also pass for those files. Changed Markdown files pass
markdownlint, and added/changed prose passes the repository cspell configuration.
Local tool child processes use `DOTNET_ROOT` and `PATH` from the task SDK directory,
so the format build host can find its matching runtime.

## Installed-payload validation preparation

The integration-test-only `BEACON_TEST_TRACER_HOME` variable selects an already
extracted or installed tracer directory. It changes the startup hook, native
profiler and dependency paths together; it is not a runtime product setting.
This permits testing a package without replacing the developer's build tree.

The Windows MSI CI validation now supplies a `ValidateInstalled` callback to
`packaging/windows/test-msi.ps1`. It builds the Smoke/MinimalApi fixtures and runs
Security unit/integration checks for .NET 8, .NET 9 and .NET 10 against the actual
installed directory. The callback runs before the legacy CLI check enables
profiling in the parent shell. Uninstall runs in `finally` if validation fails,
and CI retains available test reports. The fixed process fixture uses the system
`CMD.EXE` with guarded echo inputs for shell scripts, and the system identity
command with fixed invalid arguments for ordinary arguments; it permits no
arbitrary input. These Windows execution checks are prepared, not locally run.

The MSI script and its extracted CI callback parse without syntax errors using
the PowerShell language parser. Parsing on Linux does not validate Windows or
PowerShell 5.1 execution. The pinned contract JSON files explicitly retain LF in
Git. A temporary-index test with `core.autocrlf=true` verifies their digest after
checkout without changing the user's index.

The updated Release Linux x64 archive was extracted and used directly through
`BEACON_TEST_TRACER_HOME` to run all 38 Security integration cases on each of .NET
8, .NET 9 and .NET 10 successfully. Its managed profiler DLL was byte-compared
with the current Release build before testing. This validates the current package
and test-home routing, not Windows installation. The latest five changed C# files
also pass the solution-based format check; the total changed-file coverage is 58.

macOS ARM64 CI is also prepared to build a native tracer and run the same Security
selection on .NET 8, .NET 9 and .NET 10. The process fixture permits macOS's fixed
shell/echo paths as well as Linux and Windows equivalents. The workflow parses
as YAML and its shell step passes syntax checking; macOS execution remains open.
