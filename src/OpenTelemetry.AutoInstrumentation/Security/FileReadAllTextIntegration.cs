// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Instrumentations;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Observes a modeled request-input flow to a file read invocation.
/// </summary>
[InstrumentMethod("System.Private.CoreLib", "System.IO.File", "ReadAllText", "System.String", ["System.String"], "6.0.0", "10.*.*", "Security", InstrumentationType.Security)]
public static class FileReadAllTextIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance, string path)
    {
        SecuritySinks.ReadFile(path);
        return CallTargetState.GetDefault();
    }
}
