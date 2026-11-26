// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;
using OpenTelemetry.Logs;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityRuntimeTests
{
    [Theory]
    [InlineData(null, 300)]
    [InlineData("0", 300)]
    [InlineData("-1", 300)]
    [InlineData("bad", 300)]
    [InlineData("1", 1)]
    [InlineData("2147483647", int.MaxValue)]
    public void RefreshUsesPositiveIntegers(string? configured, int expected)
    {
        Assert.Equal(expected, SecurityRuntime.ReadRefreshSeconds(_ => configured));
    }

    [Fact]
    public void SecurityDefaultsOffAndSbomDefaultsOn()
    {
        Assert.False(SecurityRuntime.ReadBoolean(_ => null, "BEACON_SECURITY_ENABLED", false));
        Assert.True(SecurityRuntime.ReadBoolean(_ => null, "BEACON_SECURITY_SBOM_ENABLED", true));
        Assert.False(SecurityRuntime.ReadBoolean(_ => "invalid", "BEACON_SECURITY_ENABLED", false));
    }

    [Fact]
    public async Task InitialCollectionIsAsynchronousAndShutdownCancelsLongDelay()
    {
        var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var runtime = new SecurityRuntime(record => received.TrySetResult(record), int.MaxValue, () => []);
        await AssertCompletesWithinTimeout(received.Task).ConfigureAwait(true);
        var document = JObject.Parse(await received.Task.ConfigureAwait(true));
        Assert.True((long)document["uptime_ms"]! >= 0);
        runtime.Dispose();
        await AssertCompletesWithinTimeout(runtime.Completion).ConfigureAwait(true);
        await runtime.Completion.ConfigureAwait(true);
    }

    [Fact]
    public async Task FailedScanDoesNotPublishAnEmptyReplacement()
    {
        var attempted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var emitted = 0;
        using var runtime = new SecurityRuntime(_ => Interlocked.Increment(ref emitted), 300, () =>
        {
            attempted.TrySetResult(true);
            throw new InvalidOperationException("Simulated scan failure.");
        });
        await AssertCompletesWithinTimeout(attempted.Task).ConfigureAwait(true);
        runtime.Dispose();
        await AssertCompletesWithinTimeout(runtime.Completion).ConfigureAwait(true);
        await runtime.Completion.ConfigureAwait(true);
        Assert.Equal(0, emitted);
    }

    [Fact]
    public async Task FailedScanRecoversOnTheNextRound()
    {
        var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var attempts = 0;
        using var runtime = new SecurityRuntime(record => received.TrySetResult(record), 1, () =>
        {
            if (Interlocked.Increment(ref attempts) == 1)
            {
                throw new InvalidOperationException("Simulated transient scan failure.");
            }

            return [new RuntimeInventory.Dependency("Recovered", "1.0.0.0")];
        });
        await AssertCompletesWithinTimeout(received.Task).ConfigureAwait(true);
        runtime.Dispose();
        await AssertCompletesWithinTimeout(runtime.Completion).ConfigureAwait(true);
        await runtime.Completion.ConfigureAwait(true);
        var document = JObject.Parse(await received.Task.ConfigureAwait(true));
        Assert.Equal("Recovered", (string?)document["dependencies"]![0]!["name"]);
        Assert.True(attempts >= 2);
    }

    [Fact]
    public async Task ShutdownDuringScanPreventsLatePublication()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var emitted = 0;
        using var runtime = new SecurityRuntime(_ => Interlocked.Increment(ref emitted), 300, () =>
        {
            entered.Set();
            release.Wait(TimeSpan.FromSeconds(10));
            return [new RuntimeInventory.Dependency("Late", "1.0.0.0")];
        });
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            runtime.Dispose();
        }
        finally
        {
            release.Set();
        }

        await AssertCompletesWithinTimeout(runtime.Completion).ConfigureAwait(true);
        await runtime.Completion.ConfigureAwait(true);
        Assert.Equal(0, emitted);
    }

    [Fact]
    public async Task FailedLocalEnqueueDoesNotSuppressOnlineInventory()
    {
        var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var runtime = new SecurityRuntime(
            record => received.TrySetResult(record),
            300,
            () => [],
            _ => throw new IOException("Simulated local enqueue failure."));
        await AssertCompletesWithinTimeout(received.Task).ConfigureAwait(true);
        runtime.Dispose();
        await AssertCompletesWithinTimeout(runtime.Completion).ConfigureAwait(true);
        await runtime.Completion.ConfigureAwait(true);
        Assert.Empty((JArray)JObject.Parse(await received.Task.ConfigureAwait(true))["dependencies"]!);
    }

    [Fact]
    public void EmitsInventoryThroughSdkWithSecurityScopeAndDispatchAttributes()
    {
        var builder = (LoggerProviderBuilder)typeof(Sdk).GetMethod("CreateLoggerProviderBuilder", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, null)!;
        using var exporter = new CapturingExporter();
        using var processor = new SimpleLogRecordExportProcessor(exporter);
        using var provider = builder.AddProcessor(processor).Build();
        const string logical = "{\"schema_version\":2,\"source\":\"beacon_security_sbom\",\"event_name\":\"beacon.security.sbom.inventory\",\"instance_id\":\"test\",\"observed_at\":\"2026-10-02T00:00:00Z\",\"started_at\":\"2026-10-02T00:00:00Z\",\"uptime_ms\":0,\"dependencies\":[]}";
        new SecurityLogEmitter(provider).EmitInventory(logical);
        Assert.Equal(SecurityLogRecord.Bind(logical).Body, exporter.Body);
        Assert.Contains(exporter.Attributes, pair => pair.Key == "source" && Equals(pair.Value, "beacon_security_sbom"));
        Assert.Contains(exporter.Attributes, pair => pair.Key == "event.name" && Equals(pair.Value, "beacon.security.sbom.inventory"));
        Assert.Equal("INFO", exporter.SeverityText);
    }

    private static async Task AssertCompletesWithinTimeout(Task task)
    {
#if NET
        await task.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(true);
#else
        using var timeoutCancellation = new CancellationTokenSource();
        try
        {
            Assert.Same(task, await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(10), timeoutCancellation.Token)).ConfigureAwait(true));
            await task.ConfigureAwait(true);
        }
        finally
        {
            timeoutCancellation.Cancel();
        }
#endif
    }

    private sealed class CapturingExporter : BaseExporter<LogRecord>
    {
        public string? Body { get; private set; }

        public string? SeverityText { get; private set; }

        public IReadOnlyList<KeyValuePair<string, object?>> Attributes { get; private set; } = [];

        public override ExportResult Export(in Batch<LogRecord> batch)
        {
            foreach (var record in batch)
            {
                Body = record.Body;
                SeverityText = (string?)typeof(LogRecord).GetProperty("SeverityText", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.GetValue(record);
                Attributes = record.Attributes?.ToArray() ?? [];
            }

            return ExportResult.Success;
        }
    }
}
