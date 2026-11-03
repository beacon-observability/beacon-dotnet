// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Instrumentations;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Observes modeled request-input flows at a process invocation attempt.
/// </summary>
[InstrumentMethod("System.Diagnostics.Process", "System.Diagnostics.Process", "Start", "System.Boolean", [], "6.0.0", "10.*.*", "Security", InstrumentationType.Security)]
public static class ProcessStartIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance)
    {
        if (instance is Process process)
        {
            SecurityProcessSink.Observe(process.StartInfo);
        }

        return CallTargetState.GetDefault();
    }
}
