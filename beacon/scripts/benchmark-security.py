#!/usr/bin/env python3
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Measure one bounded loopback query/concat/file workload in fresh processes."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dotnet", default=shutil.which("dotnet"))
    parser.add_argument("--framework", choices=("net8.0", "net10.0"), default="net8.0")
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("this benchmark driver currently validates Linux x64 only")
    if not args.dotnet or not 100 <= args.requests <= 10000 or not 1 <= args.runs <= 20:
        parser.error("dotnet, 100..10000 requests and 1..20 runs are required")
    if args.output.exists():
        parser.error("output already exists")

    root = Path(__file__).resolve().parents[2]
    home = root / "bin/tracer-home"
    app = root / "test/test-applications/integrations/bin/TestApplication.MinimalApi/x64/Release" / args.framework / "TestApplication.MinimalApi.dll"
    if not app.is_file() or not (home / "instrument.sh").is_file():
        parser.error("build tracer-home and the Release/x64 MinimalApi fixture first")
    dotnet = str(Path(args.dotnet).resolve())
    base = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("OTEL_", "BEACON_SECURITY_", "BEACON_TEST_SECURITY_", "CORECLR_", "COR_"))
        and key not in ("DOTNET_STARTUP_HOOKS", "DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "DOTNET_ROLL_FORWARD", "DOTNET_ROLL_FORWARD_TO_PRERELEASE")
    }
    base.update({
        "ASPNETCORE_URLS": "http://127.0.0.1:0",
        "BEACON_TEST_SECURITY_BENCHMARK": str(args.requests),
        "OTEL_DOTNET_AUTO_HOME": str(home),
        "OTEL_DOTNET_AUTO_TRACES_ENABLED": "false",
        "OTEL_DOTNET_AUTO_METRICS_ENABLED": "false",
        "OTEL_DOTNET_AUTO_LOGS_ENABLED": "false",
        "OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED": "false",
        "OTEL_TRACES_EXPORTER": "none",
        "OTEL_METRICS_EXPORTER": "none",
        "OTEL_LOGS_EXPORTER": "none",
        "OTEL_LOG_LEVEL": "error",
        "BEACON_SECURITY_SBOM_ENABLED": "false",
        "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED": "false",
    })
    profiles = ("baseline", "agent", "security", "logs")
    samples = []
    for run in range(args.runs):
        order = profiles if run % 2 == 0 else profiles[::-1]
        for mode in order:
            env = dict(base)
            env["BEACON_TEST_SECURITY_BENCHMARK_MODE"] = mode
            env["BEACON_SECURITY_ENABLED"] = "true" if mode in ("security", "logs") else "false"
            env["OTEL_DOTNET_AUTO_LOGS_ENABLED"] = "true" if mode == "logs" else "false"
            command = [dotnet, str(app)]
            if mode != "baseline":
                command = ["sh", str(home / "instrument.sh"), *command]
            completed = subprocess.run(command, env=env, cwd=root, capture_output=True, text=True, timeout=120, check=False)
            if completed.returncode:
                # Do not dump application output, which could contain unrelated logs.
                raise RuntimeError(f"benchmark process failed: run={run + 1}, mode={mode}, exit={completed.returncode}")
            lines = [line.removeprefix("SECURITY_BENCHMARK=") for line in completed.stdout.splitlines() if line.startswith("SECURITY_BENCHMARK=")]
            if len(lines) != 1:
                raise RuntimeError(f"expected one benchmark result for {mode}; rebuild the fixture")
            sample = json.loads(lines[0])
            major = args.framework.removeprefix("net").split(".")[0]
            if sample["mode"] != mode or sample["requests"] != args.requests or not sample["runtime"].startswith(f".NET {major}."):
                raise RuntimeError("benchmark result does not match requested configuration")
            sample["run"] = run + 1
            samples.append(sample)
            print(f"run={run + 1} mode={mode} wallMs={sample['wallMs']:.3f} p95Ms={sample['p95Ms']:.3f}", file=sys.stderr, flush=True)

    metrics = ("wallMs", "cpuMs", "allocatedBytes", "p50Ms", "p95Ms")
    medians = {mode: {metric: statistics.median(sample[metric] for sample in samples if sample["mode"] == mode) for metric in metrics} for mode in profiles}
    report = {
        "measuredAt": datetime.now(timezone.utc).isoformat(),
        "sourceCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "sourceDirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True)),
        "framework": args.framework,
        "os": platform.system(),
        "architecture": platform.machine(),
        "availableCpuCount": len(os.sched_getaffinity(0)),
        "artifactSha256": {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                app,
                home / "net/OpenTelemetry.AutoInstrumentation.dll",
                home / "linux-x64/OpenTelemetry.AutoInstrumentation.Native.so",
                home / "net/OpenTelemetry.AutoInstrumentation.Loader.dll",
                home / "net/OpenTelemetry.AutoInstrumentation.StartupHook.dll",
                Path(__file__).resolve(),
            )
        },
        "requestsPerSample": args.requests,
        "runsPerMode": args.runs,
        "profiles": {
            "baseline": "no startup hook or CLR profiler",
            "agent": "agent enabled, Security disabled",
            "security": "Security enabled, logs disabled",
            "logs": "Security and logs enabled, exporter none",
        },
        "excluded": ["process startup", "initial JIT warmup", "SBOM", "local files", "OTLP network", "traces", "metrics"],
        "medians": medians,
        "samples": samples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(args.output)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
        print(f"Benchmark failed: {error}", file=sys.stderr)
        sys.exit(1)
