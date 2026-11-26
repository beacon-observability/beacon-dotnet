// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecuritySiemTests
{
    [Fact]
    public void ReferenceVectorsPreserveRawEvidenceAndIdentity()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "Security", "spec");
        var vectors = JObject.Parse(File.ReadAllText(Path.Combine(root, "test-vectors", "siem-v1.json")));
        foreach (var vector in vectors["vectors"]!)
        {
            var raw = File.ReadAllText(Path.Combine(root, (string)vector["input"]!));
            var resource = vector["resource"]!.ToObject<Dictionary<string, string>>()!;
            var context = vector["context"]!.ToObject<Dictionary<string, string>>()!;
            var actual = JObject.Parse(SecuritySiem.Encode(raw, resource, context));
            var expected = JObject.Parse(File.ReadAllText(Path.Combine(root, (string)vector["expected"]!)));
            Assert.True(JToken.DeepEquals(expected, actual), (string?)vector["name"]);
            Assert.Equal(raw, (string?)actual["message"]);
        }
    }

    [Theory]
    [InlineData("127.1", "")]
    [InlineData("192.0.2.1:8080", "")]
    [InlineData("[2001:db8::1]", "")]
    [InlineData("192.0.2.1", "192.0.2.1")]
    [InlineData("2001:db8::1", "2001:db8::1")]
    public void OnlyValidatedClientAddressesAreProjected(string input, string expected)
    {
        var raw = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Security", "spec", "examples", "finding-v2.json"));
        var context = new Dictionary<string, string> { ["client_ip"] = input };
        Assert.Equal(expected, (string?)JObject.Parse(SecuritySiem.Encode(raw, context: context))["ip"]);
    }

    [Fact]
    public void WireBudgetIncludesEscapingAndResourceEnrichment()
    {
        var resource = new Dictionary<string, string> { ["service.name"] = new string('界', 100), ["tenant.id"] = new string('t', 100) };
        var entries = Enumerable.Range(0, 100).Select(i => new RuntimeInventory.Dependency(i + new string('界', 30) + "\"", "1")).ToArray();
        var records = RuntimeInventory.Encode(entries, "01234567-89ab-cdef-0123-456789abcdef", DateTime.UtcNow, DateTime.UtcNow, 1, 4096, raw => Encoding.UTF8.GetByteCount(SecuritySiem.Encode(raw, resource)));
        Assert.True(records.Length > 1);
        Assert.Equal(entries.Length, records.Sum(raw => ((JArray)JObject.Parse(raw)["dependencies"]!).Count));
        foreach (var record in records)
        {
            Assert.True(Encoding.UTF8.GetByteCount(SecuritySiem.Encode(record, resource)) <= 4096);
        }
    }

    [Fact]
    public void NoEvidenceIsFilteredWithoutSuppressingUnknownOrSuspected()
    {
        Assert.False(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.NoEvidence, false));
        Assert.True(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.NoEvidence, true));
        Assert.True(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.Unknown, false));
        Assert.True(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.Suspected, false));
    }
}
