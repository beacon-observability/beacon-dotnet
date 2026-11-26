# Security log binding adoption validation

Current source pins specification `d9d76e5a41d974d294bb596e06918bb954319bf6`
and output profile `beacon-security-log-body-v1`. This is source validation,
not release acceptance or a claim about every receiver.

The producer retains v2 fields at their existing paths, moves `observed_at` to
native event time and `occurrence_id` to log attribute `event_id`, and emits a
compact single-line JSON Body. The original inventory identity tuple and
fingerprint v1 remain unchanged. Byte budgets use the transmitted UTF-8 Body.

## Verification

- The contract digest checker and its mutation/checkout regression suite passed.
- An isolated .NET SDK 8.0.416 harness compiled the actual binding, emitter, finding, fingerprint, taint and inventory sources against cached OpenTelemetry 1.19.1. All 30 selected tests passed, including native SDK time/ID preservation, normative binding examples, invalid/unrepresentable timestamps and multipart budgets. Whitespace formatting for those linked sources passed.
- Integration assertions now read time and event IDs from LogRecord metadata and use detection-time `span_id`. Local diagnostics continue to retain complete logical v2 events.
- The no-evidence export-policy tests passed in the isolated harness. Host `Instrumentation` references were supplied by a fixture stub for compilation; the tests exercise the actual policy helper, not host startup or complete request export.

## Remaining acceptance

The current repository requires SDK 11.0.100 and targets .NET 10/11; only SDK
8.0.416 is installed locally. Therefore the full distribution build, normal unit
test project, native profiler/integration tests and the target-runtime OTLP path
have not been validated. The isolated harness is not target-platform acceptance.
The .NET SDK uses 100-nanosecond DateTime precision; unsupported input precision
fails explicitly instead of being silently rounded.

## Main-branch conflict reconciliation

Reconciled the SIEM source update from main without restoring SIEM envelopes on
either producer path. Kept custom measurement hooks and downstream reference
tests, updated lifecycle tests to read logical diagnostics, and packaged the
new Body schema alongside its provenance. The contract mutation tests, package
round-trip checks and logical-event validator passed. An expanded isolated SDK 8
harness passed 51 tests, including the actual inventory worker and SDK emitter.
Host configuration/logging types remain fixture stubs; full .NET 10/11 and native
profiler validation still requires SDK 11.
