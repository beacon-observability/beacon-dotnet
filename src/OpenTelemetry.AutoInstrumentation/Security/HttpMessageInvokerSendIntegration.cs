// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Net.Http;
using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Instrumentations;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Observes a tracked request source reaching an HTTP destination invocation.
/// </summary>
[InstrumentMethod("System.Net.Http", "System.Net.Http.HttpMessageInvoker", "SendAsync", "System.Threading.Tasks.Task`1[System.Net.Http.HttpResponseMessage]", ["System.Net.Http.HttpRequestMessage", "System.Threading.CancellationToken"], "6.0.0", "10.*.*", "Security", InstrumentationType.Security)]
public static class HttpMessageInvokerSendIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        SecurityHttpSink.Observe(request);
        return CallTargetState.GetDefault();
    }
}
