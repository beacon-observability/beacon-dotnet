// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using System.Globalization;
using OpenTelemetry.AutoInstrumentation.Logging;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class SecurityRuntime : IDisposable
{
    private static readonly IOtelLogger Logger = OtelLogging.GetLogger();
    private readonly object _gate = new();
#pragma warning disable CA2213 // Disposed asynchronously after the worker stops using its token.
    private readonly CancellationTokenSource _cancellation = new();
#pragma warning restore CA2213
    private readonly Task _worker;
    private bool _disposed;

    internal SecurityRuntime(Action<string> emit, int refreshSeconds, Func<RuntimeInventory.Dependency[]> collect, Action<string[]>? snapshot = null)
    {
        var token = _cancellation.Token;
        _worker = Task.Run(async () =>
        {
            try
            {
                using var process = Process.GetCurrentProcess();
                var startedAt = process.StartTime.ToUniversalTime();
                var baselineUptime = Math.Max(0, (long)(DateTime.UtcNow - startedAt).TotalMilliseconds);
                var stopwatch = Stopwatch.StartNew();
                var instanceId = SecurityIdentity.InstanceId;
                var previousObservedAt = DateTime.MinValue;
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        var observedAt = DateTime.UtcNow;
                        if (observedAt <= previousObservedAt)
                        {
                            observedAt = previousObservedAt.AddTicks(1);
                        }

                        previousObservedAt = observedAt;
                        var uptime = baselineUptime + stopwatch.ElapsedMilliseconds;
                        var records = RuntimeInventory.Encode(collect(), instanceId, observedAt, startedAt, uptime, 65536);
                        lock (_gate)
                        {
                            if (_disposed)
                            {
                                return;
                            }

                            try
                            {
                                snapshot?.Invoke(records);
                            }
                            catch (Exception exception)
                            {
                                Logger.Error(exception, "Beacon Security local inventory enqueue failed.");
                            }

                            foreach (var record in records)
                            {
                                emit(record);
                            }
                        }
                    }
                    catch (Exception exception)
                    {
                        // A failed scan or partial transport failure must never clear inventory.
                        Logger.Error(exception, "Beacon Security inventory collection or emission failed.");
                    }

                    // Task.Delay has a bounded millisecond range on .NET Framework.
                    // Chunk long positive intervals without changing their configured duration.
                    var remaining = (long)refreshSeconds * 1000;
                    while (remaining > 0)
                    {
                        var delay = (int)Math.Min(remaining, int.MaxValue);
                        await Task.Delay(delay, token).ConfigureAwait(false);
                        remaining -= delay;
                    }
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                // Normal shutdown; do not emit an extra event or retain a replay backlog.
            }
            catch (Exception exception)
            {
                Logger.Error(exception, "Beacon Security inventory worker failed.");
            }
        });
    }

    public static bool Enabled => ReadBoolean(Environment.GetEnvironmentVariable, "BEACON_SECURITY_ENABLED", false);

    internal Task Completion => _worker;

    public static bool ReadBoolean(Func<string, string?> getValue, string key, bool defaultValue)
    {
        return bool.TryParse(getValue(key), out var value) ? value : defaultValue;
    }

    public static int ReadRefreshSeconds(Func<string, string?> getValue)
    {
        return int.TryParse(getValue("BEACON_SECURITY_SBOM_REFRESH_SECONDS"), NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value > 0 ? value : 300;
    }

    public static SecurityRuntime? TryStart(SecurityLocalOutput? localOutput = null)
    {
        try
        {
            if (!Instrumentation.GeneralSettings.Value.SetupSdk || !Enabled || !ReadBoolean(Environment.GetEnvironmentVariable, "BEACON_SECURITY_SBOM_ENABLED", true))
            {
                return null;
            }

            SecurityLogEmitter? emitter = null;
            try
            {
                var provider = Instrumentation.LoggerProvider;
                if (provider is not null)
                {
                    emitter = new SecurityLogEmitter(provider);
                }
            }
            catch (Exception exception)
            {
                Logger.Error(exception, "Beacon Security OTEL Logs initialization failed.");
            }

            if (emitter is null && localOutput is null)
            {
                return null;
            }

            return new SecurityRuntime(
                record => emitter?.EmitInventory(record),
                ReadRefreshSeconds(Environment.GetEnvironmentVariable),
                () => RuntimeInventory.Collect(AppDomain.CurrentDomain.GetAssemblies(), 4096),
                records => localOutput?.PublishInventory(records));
        }
        catch (Exception exception)
        {
            Logger.Error(exception, "Beacon Security initialization failed.");
            return null;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _cancellation.Cancel();
            _worker.GetAwaiter().OnCompleted(_cancellation.Dispose);
        }
    }
}
