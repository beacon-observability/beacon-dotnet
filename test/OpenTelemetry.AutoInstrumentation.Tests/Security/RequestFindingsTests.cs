// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class RequestFindingsTests
{
    private static readonly RequestFindings.Sink SqlSink = new("DbCommand.ExecuteReader", "sql_template", "Orders.Find");

    [Fact]
    public void DeduplicatesAndRetainsStrongestEvidenceInOneRequest()
    {
        var findings = new RequestFindings("app-test");
        var ranges = Ranges();
        findings.Observe("sql_injection", SqlSink, ranges, Evidence(RequestFindings.EvidenceStatus.NoEvidence));
        findings.Observe("sql_injection", SqlSink, ranges, Evidence(RequestFindings.EvidenceStatus.Unknown));
        findings.Observe("sql_injection", SqlSink, ranges, Evidence(RequestFindings.EvidenceStatus.Suspected));
        findings.Observe("sql_injection", SqlSink, ranges, Evidence(RequestFindings.EvidenceStatus.NoEvidence));
        var observation = Assert.Single(findings.Close());
        Assert.Equal(RequestFindings.EvidenceStatus.Suspected, observation.Evidence.Status);
        Assert.Empty(findings.Close());
    }

    [Fact]
    public void SeparateRequestsHaveStableFindingButDistinctOccurrencesAndEvidence()
    {
        var first = new RequestFindings("app-test");
        var second = new RequestFindings("app-test");
        first.Observe("sql_injection", SqlSink, Ranges(), Evidence(RequestFindings.EvidenceStatus.Suspected));
        second.Observe("sql_injection", SqlSink, Ranges(), Evidence(RequestFindings.EvidenceStatus.NoEvidence));
        var one = Assert.Single(first.Close());
        var two = Assert.Single(second.Close());
        Assert.Equal(one.FindingId, two.FindingId);
        Assert.NotEqual(one.OccurrenceId, two.OccurrenceId);
        Assert.Equal(RequestFindings.EvidenceStatus.NoEvidence, two.Evidence.Status);
    }

    [Fact]
    public void CapacityAndMissingTaintDoNotInventObservations()
    {
        var findings = new RequestFindings("app-test", capacity: 1);
        findings.Observe("sql_injection", SqlSink, [], Evidence(RequestFindings.EvidenceStatus.Unknown));
        findings.Observe("sql_injection", SqlSink, Ranges(), Evidence(RequestFindings.EvidenceStatus.Unknown));
        findings.Observe("sql_injection", new RequestFindings.Sink(SqlSink.Function, SqlSink.Role, "Other.Find"), Ranges(), Evidence(RequestFindings.EvidenceStatus.Unknown));
        Assert.False(findings.Complete);
        Assert.Single(findings.Close());
        findings.Observe("sql_injection", SqlSink, Ranges(), Evidence(RequestFindings.EvidenceStatus.Unknown));
        Assert.Empty(findings.Close());
    }

    [Fact]
    public async Task ParallelSinkCallbacksProduceOneOccurrence()
    {
        var findings = new RequestFindings("app-test");
        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => Task.Run(() => findings.Observe("sql_injection", SqlSink, Ranges(), Evidence(RequestFindings.EvidenceStatus.Unknown))))).ConfigureAwait(true);
        Assert.Single(findings.Close());
    }

    private static RequestTaint.TaintedRange[] Ranges()
    {
        return [new RequestTaint.TaintedRange(new RequestTaint.SourceInfo("source-1", "http.request.parameter", "id", "request.query", 3), 0, 3)];
    }

    private static RequestFindings.AttackEvidence Evidence(RequestFindings.EvidenceStatus status)
    {
        return new RequestFindings.AttackEvidence(status, "test_analysis");
    }
}
