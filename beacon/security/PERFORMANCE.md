# Security performance measurements

`beacon/scripts/benchmark-security.py` measures a fixed, single-client loopback
HTTP workload on Linux x64. Each request retains a query string through one
`String.Concat` into an attempted `File.ReadAllText` under a unique nonexistent
temporary directory. No files are created at that read destination. A probe
outside the timing window checks retained taint and an actual native finding;
missing instrumentation fails the benchmark instead of producing a faster sample.

Each fresh process warms 50 requests and then measures the configured request
count. The driver alternates mode order across repeated runs and records every
sample, per-mode medians, runtime version and hashes of the fixture, profiler,
loader, startup hook and benchmark driver. Source commit and dirty state are
recorded because local uncommitted changes cannot be identified by HEAD alone.

| Mode | Configuration |
| --- | --- |
| `baseline` | No startup hook or CLR profiler. |
| `agent` | Agent enabled; Security, traces, metrics and logs disabled. |
| `security` | Security detection enabled; logs disabled. |
| `logs` | Security and logs enabled; `OTEL_LOGS_EXPORTER=none`. |

SBOM and local diagnostic output are disabled in every mode. No OTLP network
traffic, traces or metrics are measured. `logs` exercises finding encoding and SDK
log submission without exporter I/O. Requests use concurrency 1; this is a narrow
small benchmark, not a production throughput, concurrency, tail-latency, startup,
local-disk or transport benchmark. CPU time and allocated bytes include the client
and server in the same process; managed allocation excludes native allocations.
CPU accounting resolution and shared-host scheduling can affect short samples.
No release overhead threshold has been agreed or inferred from these measurements.

## Reproduce

First build a Release tracer distribution and the Release fixture:

```sh
./build.sh BuildTracer --configuration Release
dotnet build test/test-applications/integrations/TestApplication.MinimalApi/TestApplication.MinimalApi.csproj -f net8.0 -c Release -p:Platform=x64
python3 beacon/scripts/benchmark-security.py --dotnet /absolute/path/to/dotnet --framework net8.0 --requests 1000 --runs 5 --output /tmp/security-performance.json
```

Use a new output path for each run. The driver rejects an existing report and
fails on a child-process error, missing result, mismatched runtime or incorrect
flow probe. It does not dump application logs on failure. For .NET 10, rebuild
the fixture with `-f net10.0` and pass `--framework net10.0` to the driver.

The dependency baseline at measurement time had a NuGet audit failure, so those
builds used `-p:NuGetAudit=false`. The separate prerequisite described in
[the implementation guide](README.md) now permits audit-enabled validation. The
saved measurements identify their original binaries and do not establish audit
or release acceptance for another revision.

## Local observations

The checked-in [net8 report](performance/linux-x64-net8-local.json) and
[net10 report](performance/linux-x64-net10-local.json) each contain 20 fresh
process samples: five runs per mode, 1000 measured requests per sample and 50
warm-up requests. Both used a Release managed profiler and a Release native
profiler, with the existing loader/startup-hook distribution identified by hash.
The host exposed an affinity of eight CPUs. Source was uncommitted, as recorded
in the reports. These measurements are evidence for this particular workload,
not an approved performance gate or a general service overhead estimate.

| Runtime | Mode | p50 ms | p95 ms | CPU ms/request | Managed bytes/request |
| --- | --- | --- | --- | --- | --- |
| 8.0.22 | baseline | 0.552 | 1.168 | 1.090 | 4195 |
| 8.0.22 | agent | 0.600 | 1.234 | 1.580 | 4984 |
| 8.0.22 | security | 0.930 | 1.439 | 1.900 | 22530 |
| 8.0.22 | logs | 1.240 | 2.997 | 3.560 | 32850 |
| 10.0.14 | baseline | 0.341 | 0.430 | 0.693 | 4063 |
| 10.0.14 | agent | 0.425 | 0.614 | 0.925 | 5693 |
| 10.0.14 | security | 0.864 | 1.954 | 2.136 | 23981 |
| 10.0.14 | logs | 1.214 | 2.619 | 3.037 | 34320 |

Each table entry is the median of the five per-process measurements; percentile
entries are medians of per-run percentiles, not percentiles pooled across runs.
Detection and finding serialization add measurable allocation and latency in
this short failing-file workload. There is substantial between-run variation;
the raw samples retain it. Fifty warm-up requests do not ensure that all tiered
JIT activity has finished, and later JIT/GC work can remain in the timed window.
The runtime runs were not simultaneous controlled A/B measurements; differences
between them do not establish a runtime-version speedup.
Startup duration, high concurrency, successful file access, other sinks, real
transport and local-output costs need separate measurement before drawing
production conclusions.
