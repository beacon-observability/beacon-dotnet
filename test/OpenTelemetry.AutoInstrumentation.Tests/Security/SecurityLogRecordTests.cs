// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using Newtonsoft.Json.Linq;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityLogRecordTests
{
    [Fact]
    public void SharedExamplesPreserveBodyIdentityAndTimestamp()
    {
        var root = Environment.GetEnvironmentVariable("BEACON_SECURITY_SPEC") ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../beacon/security"));
        foreach (var path in Directory.GetFiles(Path.Combine(root, "examples/log-records"), "*.json"))
        {
            var expected = JObject.Parse(File.ReadAllText(path));
            var inputName = Path.GetFileName(path) switch
            {
                "finding.json" => "finding-v2.json",
                "finding-occurrence.json" => "finding-occurrence-v2.json",
                "sbom-inventory.json" => "sbom-inventory-v2.json",
                var name => "siem/inputs/" + name,
            };
            var input = File.ReadAllText(Path.Combine(root, "examples", inputName));
            var actual = SecurityLogRecord.Bind(input);
            Assert.True(JToken.DeepEquals(JObject.Parse((string)expected["body"]!), JObject.Parse(actual.Body)), path);
            Assert.Equal((string?)expected["attributes"]!["event_id"], actual.EventId);
            Assert.Equal((string?)expected["time_unix_nano"], checked((actual.Timestamp.Ticks - 621355968000000000L) * 100).ToString(System.Globalization.CultureInfo.InvariantCulture));
            Assert.DoesNotContain('\n', actual.Body);
            Assert.Equal(actual.Body, SecurityLogRecord.Bind(input).Body);
            Assert.Equal(actual.EventId, SecurityLogRecord.Bind(input).EventId);
        }
    }

    [Fact]
    public void SdkReceivesNativeEventMetadataAndUnwrappedBody()
    {
        var processor = new CaptureProcessor();
        var builder = (LoggerProviderBuilder)typeof(Sdk).GetMethod("CreateLoggerProviderBuilder", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, null)!;
        using var provider = builder.AddProcessor(processor).Build();
        var emitter = new SecurityLogEmitter(provider);
        const string input = "{\"schema_version\":2,\"event_name\":\"beacon.security.finding\",\"source\":\"beacon_security\",\"observed_at\":\"2026-10-02T00:00:00.1234567Z\",\"occurrence_id\":\"one\",\"attack_evidence\":{\"status\":\"unknown\"}}";
        emitter.EmitFinding(input);
        emitter.EmitFinding(input);
        Assert.Equal(2, processor.Records.Count);
        Assert.Equal(processor.Records[0], processor.Records[1]);
        var actual = processor.Records[0];
        Assert.Equal("one", actual.Id);
        Assert.Equal(1790899200123456700L, checked((actual.Timestamp.Ticks - 621355968000000000L) * 100));
        var body = JObject.Parse(actual.Body);
        Assert.Equal(2, (int)body["schema_version"]!);
        Assert.Equal("unknown", (string?)body["attack_evidence"]!["status"]);
        Assert.Null(body["message"]);
        Assert.Null(body["observed_at"]);
        Assert.Null(body["occurrence_id"]);
    }

    private sealed class CaptureProcessor : BaseProcessor<LogRecord>
    {
        public List<(string Body, DateTime Timestamp, string Id)> Records { get; } = [];

        public override void OnEnd(LogRecord data)
        {
            Records.Add((data.Body!, data.Timestamp, (string)data.Attributes!.Single(attribute => attribute.Key == "event_id").Value!));
        }
    }

    [Theory]
    [InlineData("1970-01-01T00:00:00Z")]
    [InlineData("1969-12-31T23:59:59Z")]
    [InlineData("2263-01-01T00:00:00Z")]
    [InlineData("2026-02-30T00:00:00Z")]
    [InlineData("2026-10-02T00:00:00.123456789Z")]
    public void RejectsUnsetOutOfRangeOrUnrepresentableTime(string time)
    {
        var input = new JObject { ["event_name"] = "beacon.security.finding", ["observed_at"] = time, ["occurrence_id"] = "test" };
        Assert.ThrowsAny<Exception>(() => SecurityLogRecord.Bind(input.ToString()));
    }
}
