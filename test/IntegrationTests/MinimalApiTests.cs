// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#if NET

using System.Globalization;
using IntegrationTests.Helpers;
using Newtonsoft.Json.Linq;
using OpenTelemetry.Proto.Logs.V1;

namespace IntegrationTests;

public class MinimalApiTests : TestHelper
{
    public MinimalApiTests(ITestOutputHelper output)
        : base("MinimalApi", output)
    {
    }

    [Theory]
    [InlineData(true, true, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(false, true, true, false)]
    [InlineData(true, true, true, false)]
    [InlineData(true, true, true, true)]
    [Trait("Category", "EndToEnd")]
    public void SecurityLocalDiagnosticsRequireOptInAndDoNotControlOtlp(bool enabled, bool local, bool logs, bool brokenDirectory)
    {
        var testRoot = Path.Combine(Path.GetTempPath(), "beacon-security-integration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try
        {
            var output = Path.Combine(testRoot, "output");
            var evidence = Path.Combine(testRoot, "evidence.jsonl");
            if (brokenDirectory)
            {
                File.WriteAllText(output, "This file prevents creating a snapshot directory.");
            }

            using var collector = new MockLogsCollector(Output);
            SetExporter(collector);
            EnableBytecodeInstrumentation();
            SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
            SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
            SetEnvironmentVariable("BEACON_TEST_SECURITY_FINDING", "true");
            SetEnvironmentVariable("BEACON_TEST_SECURITY_LOCAL_DRAIN", "true");
            SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
            SetEnvironmentVariable("BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", local ? "true" : "false");
            SetEnvironmentVariable("BEACON_SECURITY_OUTPUT", output);
            SetEnvironmentVariable("BEACON_SECURITY_EVIDENCE_FILE", evidence);
            SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "true");
            SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", "false");
            SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
            SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED", "false");
            SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", logs ? "true" : "false");
            collector.ExpectCollected(records => ValidateSecurityFindings(records, enabled && logs, false) && (logs || records.Count == 0), "Local diagnostics must not change OTLP delivery.");
            RunTestApplication();
            collector.AssertCollected();

            if (!enabled || !local || brokenDirectory)
            {
                Assert.False(Directory.Exists(output));
                Assert.False(File.Exists(evidence));
                return;
            }

            var findings = File.ReadAllLines(evidence);
            Assert.Equal(2, findings.Length);
            var documents = findings.Select(JObject.Parse).ToArray();
            var instanceId = (string)documents[0]["instance_id"]!;
            Assert.Equal(instanceId, (string?)documents[1]["instance_id"]);
            Assert.NotEqual((string?)documents[0]["occurrence_id"], (string?)documents[1]["occurrence_id"]);
            var snapshotDirectory = Path.Combine(output, instanceId);
            var latest = File.ReadAllText(Path.Combine(snapshotDirectory, "finding.json"));
            Assert.Contains(latest.TrimEnd('\n'), findings);
            foreach (var finding in findings)
            {
                Assert.DoesNotContain("first-request", finding, StringComparison.Ordinal);
                Assert.DoesNotContain("second-request", finding, StringComparison.Ordinal);
                Assert.Equal("path_traversal", (string?)JObject.Parse(finding)["rule"]);
            }

            var inventories = File.ReadAllLines(Path.Combine(snapshotDirectory, "inventory.jsonl"));
            Assert.NotEmpty(inventories);
            Assert.All(inventories, inventory => Assert.Equal(instanceId, (string?)JObject.Parse(inventory)["instance_id"]));
            Assert.Empty(Directory.GetFiles(snapshotDirectory, "*.tmp"));
        }
        finally
        {
            Directory.Delete(testRoot, true);
        }
    }

    [SkippableTheory]
    [InlineData(false, false, "argument")]
    [InlineData(true, false, "argument")]
    [InlineData(true, true, "argument")]
    [InlineData(true, false, "shell")]
    [InlineData(true, true, "shell")]
    [InlineData(true, false, "constant")]
    [InlineData(true, false, "executable")]
    [Trait("Category", "EndToEnd")]
    public void SecurityProcessInvocations(bool enabled, bool tracing, string mode)
    {
        Skip.IfNot(OperatingSystem.IsLinux() || OperatingSystem.IsWindows() || OperatingSystem.IsMacOS(), "This fixed executable fixture requires Linux, Windows or macOS.");
        using var collector = new MockLogsCollector(Output);
        SetExporter(collector);
        EnableBytecodeInstrumentation();
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_PROCESS", mode);
        SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", tracing ? "true" : "false");
        SetEnvironmentVariable("OTEL_TRACES_EXPORTER", "none");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", "true");
        collector.ExpectCollected(records => ValidateProcessFindings(records, enabled && mode != "constant", mode, tracing), "Process flow findings must preserve invocation behavior and privacy.");
        RunTestApplication();
        collector.AssertCollected();
    }

    [Theory]
    [InlineData(false, false, "input")]
    [InlineData(true, false, "input")]
    [InlineData(true, true, "input")]
    [InlineData(true, false, "constant")]
    [InlineData(true, false, "query")]
    [InlineData(true, false, "path")]
    [InlineData(true, true, "query")]
    [InlineData(true, false, "fragment")]
    [Trait("Category", "EndToEnd")]
    public void SecurityHttpDestinations(bool enabled, bool tracing, string mode)
    {
        using var collector = new MockLogsCollector(Output);
        SetExporter(collector);
        EnableBytecodeInstrumentation();
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_SSRF", mode);
        SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", tracing ? "true" : "false");
        SetEnvironmentVariable("OTEL_TRACES_EXPORTER", "none");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", "true");
        collector.ExpectCollected(records => ValidateHttpFindings(records, !enabled || mode is "constant" or "fragment" ? null : mode is "query" or "path" ? "http_request_input" : "ssrf", tracing, mode == "path" ? "path" : "query"), "Only modeled request-input destinations should produce private findings.");
        RunTestApplication();
        collector.AssertCollected();
    }

    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(true, false, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, true, true, false)]
    [InlineData(true, true, false, true)]
    [InlineData(true, false, true, true)]
    [Trait("Category", "EndToEnd")]
    public void SecuritySqlTemplatesAndBoundParameters(bool enabled, bool tracing, bool parameterized, bool asynchronous)
    {
        using var collector = new MockLogsCollector(Output);
        using var spans = tracing ? new MockSpansCollector(Output) : null;
        SetExporter(collector);
        EnableBytecodeInstrumentation();
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_SQL", parameterized ? "parameterized" : "template");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_SQL_ASYNC", asynchronous ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", tracing ? "true" : "false");
        SetEnvironmentVariable("OTEL_TRACES_EXPORTER", "none");
        if (spans is not null)
        {
            SetEnvironmentVariable("OTEL_TRACES_EXPORTER", "otlp");
            SetEnvironmentVariable("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", $"http://localhost:{spans.Port}/v1/traces");
            for (var index = 0; index < 4; index++)
            {
                spans.Expect("OpenTelemetry.AutoInstrumentation.AdoNet");
            }

            spans.ExpectAllCollected(records => records.Count(record => record.Scope.Name == "OpenTelemetry.AutoInstrumentation.AdoNet") == 4);
        }

        SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", "true");
        collector.ExpectCollected(records => ValidateSqlFindings(records, enabled && !parameterized, tracing), "Only tainted SQL templates should produce deduplicated findings.");
        RunTestApplication();
        collector.AssertCollected();
        spans?.AssertExpectations();
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    [Trait("Category", "EndToEnd")]
    public void SecurityFileFindingsReachOtlpWithoutRequestValues(bool enabled, bool tracing)
    {
        using var collector = new MockLogsCollector(Output);
        SetExporter(collector);
        EnableBytecodeInstrumentation();
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_FINDING", "true");
        SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", tracing ? "true" : "false");
        SetEnvironmentVariable("OTEL_TRACES_EXPORTER", "none");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INSTRUMENTATION_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", "true");
        collector.ExpectCollected(records => ValidateSecurityFindings(records, enabled, tracing), "Security findings should be private and request-deduplicated.");
        RunTestApplication();
        collector.AssertCollected();
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 1)]
    [Trait("Category", "EndToEnd")]
    public void SecurityQuerySourcesFlowThroughAsyncConcurrentRequests(bool enabled, int expectedRanges)
    {
        EnableBytecodeInstrumentation();
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");
        SetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP", "true");
        SetEnvironmentVariable("BEACON_SECURITY_ENABLED", enabled ? "true" : "false");
        SetEnvironmentVariable("BEACON_SECURITY_SBOM_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_TRACES_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_METRICS_ENABLED", "false");
        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_ENABLED", "false");
        var (output, _, _) = RunTestApplication();
        var matches = output.Split(["HTTP_SOURCE_RANGES=" + expectedRanges], StringSplitOptions.None).Length - 1;
        Assert.Equal(2, matches);
        Assert.Contains($"HTTP_DISTINCT_SCOPES={(enabled ? 2 : 0)}", output, StringComparison.Ordinal);
    }

    [SkippableTheory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [Trait("Category", "EndToEnd")]
    public async Task SubmitsLogsWithoutDuplicates(bool enableByteCodeInstrumentation, bool enableHostingStartupAssembly)
    {
        using var collector = new MockLogsCollector(Output);
        SetExporter(collector);

        SetEnvironmentVariable("OTEL_DOTNET_AUTO_LOGS_INCLUDE_FORMATTED_MESSAGE", "true");

        // Bind to a random port.
        SetEnvironmentVariable("ASPNETCORE_URLS", "http://127.0.0.1:0");

        if (enableByteCodeInstrumentation)
        {
            EnableBytecodeInstrumentation();
            collector.ExpectCollected(ValidateCombinedLogsExport, "All log records should be exported once.");
        }

        if (enableHostingStartupAssembly)
        {
            SetEnvironmentVariable("ASPNETCORE_HOSTINGSTARTUPASSEMBLIES", "OpenTelemetry.AutoInstrumentation.AspNetCoreBootstrapper");
            if (!enableByteCodeInstrumentation)
            {
                // otherwise expectation was already set
                collector.ExpectCollected(ValidateSingleAppLogExport, "Application log records should be exported once.");
            }
        }

        RunTestApplication();

        // wait for fixed amount of time for logs to be collected before asserting
        await Task.Delay(TimeSpan.FromSeconds(10)).ConfigureAwait(false);

        collector.AssertCollected();
    }

    private static bool ValidateCombinedLogsExport(ICollection<LogRecord> records)
    {
        return ValidateSingleAppLogExport(records) && ValidateSingleBeforeHostLogRecord(records);
    }

    private static bool ValidateProcessFindings(ICollection<LogRecord> records, bool expected, string mode, bool tracing)
    {
        var findings = records.Where(record => record.Attributes.Any(attribute => attribute.Key == "source" && attribute.Value.StringValue == "beacon_security")).ToArray();
        Assert.Equal(expected ? 2 : 0, findings.Length);
        foreach (var record in findings)
        {
            var document = JObject.Parse(record.Body.StringValue);
            Assert.Equal(mode == "shell" ? "command_injection" : "command_execution", (string?)document["rule"]);
            Assert.Equal(mode == "shell" ? "shell_script" : mode == "executable" ? "executable" : "argument", (string?)document["sink"]!["role"]);
            Assert.Equal("unknown", (string?)document["attack_evidence"]!["status"]);
            Assert.DoesNotContain("first-request", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("second-request", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("printf", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("/bin/", record.Body.StringValue, StringComparison.Ordinal);
            if (tracing)
            {
                Assert.Equal(((string)document["trace_id"]!).ToUpperInvariant(), Convert.ToHexString(record.TraceId.Span));
            }
        }

        if (expected)
        {
            var first = JObject.Parse(findings[0].Body.StringValue);
            var second = JObject.Parse(findings[1].Body.StringValue);
            Assert.Equal((string?)first["finding_id"], (string?)second["finding_id"]);
            Assert.NotEqual((string?)first["occurrence_id"], (string?)second["occurrence_id"]);
        }

        return true;
    }

    private static bool ValidateHttpFindings(ICollection<LogRecord> records, string? expectedRule, bool tracing, string inputPart)
    {
        var findings = records.Where(record => record.Attributes.Any(attribute => attribute.Key == "source" && attribute.Value.StringValue == "beacon_security")).ToArray();
        Assert.Equal(expectedRule is not null ? 2 : 0, findings.Length);
        foreach (var record in findings)
        {
            var document = JObject.Parse(record.Body.StringValue);
            Assert.Equal(expectedRule, (string?)document["rule"]);
            Assert.Equal(expectedRule == "ssrf" ? "destination_address" : "path_or_query", (string?)document["sink"]!["role"]);
            if (expectedRule == "http_request_input")
            {
                Assert.Equal(inputPart, (string?)document["sink"]!["input_part"]);
            }

            Assert.Equal("unknown", (string?)document["attack_evidence"]!["status"]);
            Assert.Equal("/security-http", (string?)document["request"]!["route"]);
            Assert.DoesNotContain("127.0.0.1", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("private-marker", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("/destination", record.Body.StringValue, StringComparison.Ordinal);
            if (tracing)
            {
                Assert.Equal(((string)document["trace_id"]!).ToUpperInvariant(), Convert.ToHexString(record.TraceId.Span));
            }
        }

        if (expectedRule is not null)
        {
            var first = JObject.Parse(findings[0].Body.StringValue);
            var second = JObject.Parse(findings[1].Body.StringValue);
            Assert.Equal((string?)first["finding_id"], (string?)second["finding_id"]);
            Assert.NotEqual((string?)first["occurrence_id"], (string?)second["occurrence_id"]);
        }

        return true;
    }

    private static bool ValidateSqlFindings(ICollection<LogRecord> records, bool expected, bool tracing)
    {
        var findings = records.Where(record => record.Attributes.Any(attribute => attribute.Key == "source" && attribute.Value.StringValue == "beacon_security")).ToArray();
        Assert.Equal(expected ? 2 : 0, findings.Length);
        foreach (var record in findings)
        {
            var document = JObject.Parse(record.Body.StringValue);
            Assert.Equal("sql_injection", (string?)document["rule"]);
            Assert.Equal("sql_template", (string?)document["sink"]!["role"]);
            Assert.EndsWith(".ExecuteScalar", (string?)document["sink"]!["function"], StringComparison.Ordinal);
            Assert.Equal("unknown", (string?)document["attack_evidence"]!["status"]);
            Assert.DoesNotContain("first-request", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("second-request", record.Body.StringValue, StringComparison.Ordinal);
            Assert.DoesNotContain("SELECT", record.Body.StringValue, StringComparison.Ordinal);
            if (tracing)
            {
                Assert.Equal(((string)document["trace_id"]!).ToUpperInvariant(), Convert.ToHexString(record.TraceId.Span));
                Assert.NotNull(document["current_span_id"]);
                Assert.Equal(((string)document["current_span_id"]!).ToUpperInvariant(), Convert.ToHexString(record.SpanId.Span));
                Assert.NotEqual((string?)document["server_span_id"], (string?)document["current_span_id"]);
            }
        }

        if (expected)
        {
            var first = JObject.Parse(findings[0].Body.StringValue);
            var second = JObject.Parse(findings[1].Body.StringValue);
            Assert.Equal((string?)first["finding_id"], (string?)second["finding_id"]);
            Assert.NotEqual((string?)first["occurrence_id"], (string?)second["occurrence_id"]);
        }

        return true;
    }

    private static bool ValidateSecurityFindings(ICollection<LogRecord> records, bool enabled, bool tracing)
    {
        var findings = records.Where(record => record.Attributes.Any(attribute => attribute.Key == "source" && attribute.Value.StringValue == "beacon_security")).ToArray();
        Assert.Equal(enabled ? 2 : 0, findings.Length);
        if (!enabled)
        {
            return true;
        }

        var documents = findings.Select(record => JObject.Parse(record.Body.StringValue)).ToArray();
        if (tracing)
        {
            for (var index = 0; index < findings.Length; index++)
            {
                Assert.Equal(((string)documents[index]["trace_id"]!).ToUpperInvariant(), Convert.ToHexString(findings[index].TraceId.Span));
                Assert.Equal(((string)documents[index]["server_span_id"]!).ToUpperInvariant(), Convert.ToHexString(findings[index].SpanId.Span));
            }
        }

        Assert.Equal((string?)documents[0]["finding_id"], (string?)documents[1]["finding_id"]);
        Assert.NotEqual((string?)documents[0]["occurrence_id"], (string?)documents[1]["occurrence_id"]);
        foreach (var document in documents)
        {
            Assert.Equal(2, (int)document["schema_version"]!);
            Assert.Equal("path_traversal", (string?)document["rule"]);
            Assert.Equal("unknown", (string?)document["attack_evidence"]!["status"]);
            Assert.Equal("GET", (string?)document["request"]!["method"]);
            Assert.Equal("/security", (string?)document["request"]!["route"]);
            Assert.Equal(200, (int)document["request"]!["status_code"]!);
            Assert.Null(document["request"]!["error_type"]);
            if (tracing)
            {
                Assert.Equal(32, ((string)document["trace_id"]!).Length);
                Assert.Equal(16, ((string)document["server_span_id"]!).Length);
                Assert.Null(document["current_span_id"]);
            }

            Assert.DoesNotContain("first-request", document.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("second-request", document.ToString(), StringComparison.Ordinal);
        }

        return true;
    }

    private static bool ValidateSingleBeforeHostLogRecord(ICollection<LogRecord> records)
    {
        var beforeHostLogCount = records.Count(lr => Convert.ToString(lr.Body, CultureInfo.InvariantCulture) == "{ \"stringValue\": \"Logged before host is built.\" }");
        return beforeHostLogCount == 1;
    }

    private static bool ValidateSingleAppLogExport(ICollection<LogRecord> records)
    {
        var appLogCount = records.Count(lr => Convert.ToString(lr.Body, CultureInfo.InvariantCulture) == "{ \"stringValue\": \"Request received.\" }");
        return appLogCount == 1;
    }
}
#endif
