// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Collections;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace TestApplication.MinimalApi;

internal static class SecurityLoadScenario
{
    private static readonly string MissingDirectory = Path.Combine(Path.GetTempPath(), "beacon-security-load-" + Guid.NewGuid().ToString("N")) + Path.DirectorySeparatorChar;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Handle(string input, bool probe)
    {
        if (input != "fixed-input")
        {
            throw new InvalidOperationException("Security benchmark only permits its fixed input.");
        }

        var path = string.Concat(MissingDirectory, input);
        try
        {
            _ = File.ReadAllText(path);
        }
        catch (IOException)
        {
            // This fixed workload observes an attempted read, not successful file access.
        }

        if (!probe)
        {
            return "ok";
        }

        // Validate actual automatic query -> concat -> file flow outside timed requests.
        var assembly = AppDomain.CurrentDomain.GetAssemblies().SingleOrDefault(candidate => candidate.GetName().Name == "OpenTelemetry.AutoInstrumentation");
        var contextType = assembly?.GetType("OpenTelemetry.AutoInstrumentation.Security.SecurityRequestContext", true);
        var scope = contextType?.GetProperty("Current")!.GetValue(null);
        if (scope is null)
        {
            return "0:0";
        }

        var taint = contextType!.GetProperty("Taint")!.GetValue(scope)!;
        var ranges = (Array)taint.GetType().GetMethod("AtSink")!.Invoke(taint, [path])!;
        var findings = contextType.GetProperty("Findings")!.GetValue(scope)!;
        var observations = (IDictionary)findings.GetType().GetField("_observations", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(findings)!;
        return ranges.Length.ToString(CultureInfo.InvariantCulture) + ":" + observations.Count.ToString(CultureInfo.InvariantCulture);
    }

    public static void Run(HttpClient client, string address, string configuredRequests)
    {
        // Finish all client use before the caller's using scope disposes it.
        RunAsync(client, address, configuredRequests).GetAwaiter().GetResult();
    }

    private static async Task RunAsync(HttpClient client, string address, string configuredRequests)
    {
        var count = int.Parse(configuredRequests, NumberStyles.None, CultureInfo.InvariantCulture);
        if (count is < 100 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(configuredRequests));
        }

        var mode = Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_BENCHMARK_MODE");
        var expectedProbe = mode switch
        {
            "baseline" or "agent" => "0:0",
            "security" or "logs" => "1:1",
            _ => throw new InvalidOperationException("Unknown Security benchmark mode."),
        };
        var request = new Uri(address + "/security-load?id=fixed-input");
        if (!request.IsLoopback)
        {
            throw new InvalidOperationException("Security benchmark requires a loopback address.");
        }

        const int warmup = 50;
        for (var index = 0; index < warmup; index++)
        {
            await client.GetStringAsync(request).ConfigureAwait(false);
        }

        var probe = await client.GetStringAsync(new Uri(request.AbsoluteUri + "&probe=true")).ConfigureAwait(false);
        if (probe != expectedProbe)
        {
            throw new InvalidOperationException("Security benchmark did not observe the expected native flow.");
        }

        using var process = Process.GetCurrentProcess();
        var latencies = new double[count];
        var allocatedBefore = GC.GetTotalAllocatedBytes(true);
        var cpuBefore = process.TotalProcessorTime;
        var wall = Stopwatch.StartNew();
        for (var index = 0; index < count; index++)
        {
            var started = Stopwatch.GetTimestamp();
            var response = await client.GetStringAsync(request).ConfigureAwait(false);
            latencies[index] = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            if (response != "ok")
            {
                throw new InvalidOperationException("Unexpected benchmark response.");
            }
        }

        wall.Stop();
        var cpu = process.TotalProcessorTime - cpuBefore;
        var allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
        Array.Sort(latencies);
        var result = new
        {
            mode,
            requests = count,
            warmup,
            concurrency = 1,
            runtime = RuntimeInformation.FrameworkDescription,
            architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            flowProbe = probe,
            wallMs = wall.Elapsed.TotalMilliseconds,
            cpuMs = cpu.TotalMilliseconds,
            allocatedBytes = allocated,
            p50Ms = latencies[(int)Math.Ceiling(count * 0.5) - 1],
            p95Ms = latencies[(int)Math.Ceiling(count * 0.95) - 1],
        };
        Console.WriteLine("SECURITY_BENCHMARK=" + JsonSerializer.Serialize(result));
    }
}
