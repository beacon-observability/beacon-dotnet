// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.CompilerServices;

namespace TestApplication.Smoke;

// Tests the profiler plumbing with a manually tagged source. HTTP source and sink
// instrumentation require separate acceptance tests; this is not a finding test.
internal static class SecurityConcatScenario
{
    public static void Run()
    {
        var assembly = AppDomain.CurrentDomain.GetAssemblies().Single(candidate => candidate.GetName().Name == "OpenTelemetry.AutoInstrumentation");
        var contextType = assembly.GetType("OpenTelemetry.AutoInstrumentation.Security.SecurityRequestContext", true)!;
        using var scope = (IDisposable)contextType.GetMethod("Begin")!.Invoke(null, ["app-smoke"])!;
        var taint = contextType.GetProperty("Taint")!.GetValue(scope)!;
        var input = new string('x', 3);
        taint.GetType().GetMethod("Source")!.Invoke(taint, [input, "http.request.parameter", "id", "request.query"]);
        Report(taint, Join("prefix", input), 2);
        Report(taint, Join("prefix", input, "suffix"), 3);
        Report(taint, Join("prefix", input, "suffix", "end"), 4);
    }

    private static void Report(object taint, string result, int arity)
    {
        var ranges = (Array)taint.GetType().GetMethod("AtSink")!.Invoke(taint, [result])!;
        Console.WriteLine($"NATIVE_CONCAT_RANGES_{arity}={ranges.Length}");
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Join(string prefix, string input)
    {
        return string.Concat(prefix, input);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Join(string prefix, string input, string suffix)
    {
        return string.Concat(prefix, input, suffix);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Join(string prefix, string input, string suffix, string end)
    {
        return string.Concat(prefix, input, suffix, end);
    }
}
