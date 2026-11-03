// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class FindingTrace(ActivityTraceId traceId, ActivitySpanId serverSpanId, ActivitySpanId currentSpanId, ActivityTraceFlags flags)
{
    public ActivityTraceId TraceId { get; } = traceId;

    public ActivitySpanId ServerSpanId { get; } = serverSpanId;

    public ActivitySpanId CurrentSpanId { get; } = currentSpanId;

    public ActivityTraceFlags Flags { get; } = flags;

    public static FindingTrace? Capture()
    {
        var current = Activity.Current;
        if (current is null || current.IdFormat != ActivityIdFormat.W3C)
        {
            return null;
        }

        var server = current;
        while (server is not null && server.Kind != ActivityKind.Server)
        {
            server = server.Parent;
        }

        return new FindingTrace(current.TraceId, server?.SpanId ?? default, current.SpanId, current.ActivityTraceFlags);
    }
}
