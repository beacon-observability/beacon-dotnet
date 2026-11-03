// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class FindingEventTests
{
    [Fact]
    public void PreservesFalseValuesAndDoesNotSerializeRawSourceOrSql()
    {
        var observation = Observe("private-user-value", "id");
        var json = FindingEvent.Encode(observation, false)!;
        var document = JObject.Parse(json);
        Assert.False((bool)document["collection_complete"]!);
        Assert.True((bool)document["evidence_sampled"]!);
        Assert.Equal(2, (int)document["schema_version"]!);
        Assert.Equal("beacon.security.finding", (string?)document["event_name"]);
        Assert.Equal("beacon_security", (string?)document["source"]);
        Assert.Equal(SecurityIdentity.InstanceId, (string?)document["instance_id"]);
        Assert.Equal("unknown", (string?)document["attack_evidence"]!["status"]);
        Assert.DoesNotContain("private-user-value", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT", json, StringComparison.Ordinal);
        Assert.Null(document["sink"]!["operation"]);
        Assert.Null(document["application_id"]);
        Assert.Null(document["truncated"]);
        Assert.Equal("utf16_code_unit", (string?)document["ranges"]![0]!["unit"]);
    }

    [Fact]
    public void ByteCompactionRetainsIdentityAndDeclaresActualTruncation()
    {
        var observation = Observe("private-value", new string('界', 200));
        var full = FindingEvent.Encode(observation, true)!;
        var json = FindingEvent.Encode(observation, true, Encoding.UTF8.GetByteCount(full) - 200)!;
        var document = JObject.Parse(json);
        Assert.Equal(observation.FindingId, (string?)document["finding_id"]);
        Assert.Equal(observation.OccurrenceId, (string?)document["occurrence_id"]);
        Assert.False((bool)document["evidence_sampled"]!);
        Assert.True((bool)document["truncated"]!);
        Assert.Equal("record_byte_limit", (string?)document["truncation_reason"]);
        Assert.Null(document["sources"]);
        Assert.Null(document["ranges"]);
        Assert.True(Encoding.UTF8.GetByteCount(json) <= Encoding.UTF8.GetByteCount(full) - 200);
        Assert.Null(FindingEvent.Encode(observation, true, 1));
    }

    private static RequestFindings.Observation Observe(string value, string name)
    {
        var taint = new RequestTaint();
        taint.Source(value, "http.request.parameter", name, "request.query");
        var sql = string.Concat("SELECT ", value);
        taint.Concat(sql, ["SELECT ", value]);
        var findings = new RequestFindings("app-test");
        findings.Observe("sql_injection", new RequestFindings.Sink("DbCommand.ExecuteReader", "sql_template", "Orders.Find"), taint.AtSink(sql), new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, "unsupported_dialect"));
        return Assert.Single(findings.Close());
    }
}
