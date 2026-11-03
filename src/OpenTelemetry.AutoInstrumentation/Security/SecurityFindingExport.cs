// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecurityFindingExport
{
    private static readonly Lazy<SecurityLogEmitter?> Emitter = new(() =>
    {
        if (!Instrumentation.GeneralSettings.Value.SetupSdk || !Instrumentation.LogSettings.Value.LogsEnabled)
        {
            return null;
        }

        try
        {
            var provider = Instrumentation.LoggerProvider;
            return provider is null ? null : new SecurityLogEmitter(provider);
        }
        catch (Exception)
        {
            return null;
        }
    });

    public static void Complete(SecurityRequestContext scope, Exception? exception = null)
    {
        var observations = scope.Findings.Close();
        scope.Taint.Close();
        var complete = scope.Taint.Complete && scope.Findings.Complete;
        if (observations.Length == 0)
        {
            scope.Dispose();
            return;
        }

        RequestDetails? request;
        try
        {
            request = scope.RequestDetailsProvider?.Invoke(exception);
        }
        catch (Exception)
        {
            request = null;
        }

        scope.Dispose();

        try
        {
            var emitter = Emitter.Value;
            var localOutput = Instrumentation.LocalSecurityOutput;
            if (emitter is null && localOutput is null)
            {
                return;
            }

            foreach (var observation in observations)
            {
                var json = FindingEvent.Encode(observation, complete, request: request);
                if (json is not null)
                {
                    localOutput?.PublishFinding(json);
                    try
                    {
                        emitter?.EmitFinding(json, observation.Trace);
                    }
                    catch (Exception)
                    {
                        // A transport failure must not suppress later local snapshots.
                    }
                }
            }
        }
        catch (Exception)
        {
            // Export is best effort. Never affect the application's response or exception.
        }
    }
}
