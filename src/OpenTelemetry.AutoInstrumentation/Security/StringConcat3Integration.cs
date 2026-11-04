// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Instrumentations;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Propagates request-local ranges through string concatenation.
/// </summary>
[InstrumentMethod("System.Private.CoreLib", "System.String", "Concat", "System.String", ["System.String", "System.String", "System.String"], "6.0.0", "10.*.*", "Security", InstrumentationType.Security)]
[InstrumentMethod("mscorlib", "System.String", "Concat", "System.String", ["System.String", "System.String", "System.String"], "4.0.0", "4.*.*", "Security", InstrumentationType.Security)]
public static class StringConcat3Integration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance, string? value0, string? value1, string? value2)
    {
        return SecurityRequestContext.Current is null ? CallTargetState.GetDefault() : StringConcatHooks.Begin([value0, value1, value2]);
    }

    internal static CallTargetReturn<string> OnMethodEnd<TTarget>(TTarget instance, string returnValue, Exception? exception, in CallTargetState state)
    {
        StringConcatHooks.End(returnValue, exception, in state);
        return new CallTargetReturn<string>(returnValue);
    }
}
