// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Instrumentations;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Establishes a Security scope for the asynchronous ASP.NET Core request pipeline.
/// </summary>
// The native signature reader reports this nested TypeDef as "Context".
[InstrumentMethod("Microsoft.AspNetCore.Hosting", "Microsoft.AspNetCore.Hosting.HostingApplication", "ProcessRequestAsync", "System.Threading.Tasks.Task", ["Context"], "6.0.0", "10.*.*", "Security", InstrumentationType.Security)]
public static class AspNetCoreRequestIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget, TContext>(TTarget instance, TContext context)
    {
        return new CallTargetState(null, HttpRequestTracking.Begin(context!));
    }

    internal static TReturn OnAsyncMethodEnd<TTarget, TReturn>(TTarget instance, TReturn returnValue, Exception? exception, in CallTargetState state)
    {
        if (state.State is SecurityRequestContext scope)
        {
            SecurityFindingExport.Complete(scope, exception);
        }

        return returnValue;
    }
}
