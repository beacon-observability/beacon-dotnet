// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class FindingTraceTests
{
    [Fact]
    public void DistinguishesServerAndCurrentSpansAndRetainsCaptureAfterSpanEnds()
    {
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == "SecurityTraceTests",
            Sample = (ref ActivityCreationOptions<ActivityContext> options) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        using var source = new ActivitySource("SecurityTraceTests");
        using var server = source.StartActivity("server", ActivityKind.Server)!;
        var atServer = FindingTrace.Capture()!;
        Assert.Equal(server.TraceId, atServer.TraceId);
        Assert.Equal(server.SpanId, atServer.ServerSpanId);
        Assert.Equal(atServer.ServerSpanId, atServer.CurrentSpanId);
        FindingTrace snapshot;
        using (var child = source.StartActivity("child", ActivityKind.Internal)!)
        {
            snapshot = FindingTrace.Capture()!;
            Assert.Equal(child.SpanId, snapshot.CurrentSpanId);
        }

        Assert.NotEqual(server.SpanId, snapshot.CurrentSpanId);
        var range = new RequestTaint.TaintedRange(new RequestTaint.SourceInfo("source-1", "http.request.parameter", "id", "request.query", 3), 0, 3);
        var observation = new RequestFindings.Observation("finding-" + new string('a', 64), "occurrence-test", "path_traversal", new RequestFindings.Sink("File.ReadAllText", "file_path", "App.Read"), [range], new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, "unknown_policy"), trace: snapshot);
        var document = JObject.Parse(FindingEvent.Encode(observation, true, request: new RequestDetails("GET", "/files/{id}", 404, null))!);
        Assert.Equal(server.TraceId.ToHexString(), (string?)document["trace_id"]);
        Assert.Equal(server.SpanId.ToHexString(), (string?)document["server_span_id"]);
        Assert.Equal(snapshot.CurrentSpanId.ToHexString(), (string?)document["current_span_id"]);
        Assert.Equal("/files/{id}", (string?)document["request"]!["route"]);
        Assert.Equal(404, (int)document["request"]!["status_code"]!);
        Assert.Null(document["request"]!["error_type"]);
        var serverOnly = new RequestFindings.Observation(observation.FindingId, observation.OccurrenceId, observation.Rule, observation.Sink, observation.Ranges, observation.Evidence, trace: atServer);
        Assert.Null(JObject.Parse(FindingEvent.Encode(serverOnly, true)!)["current_span_id"]);
    }
}
