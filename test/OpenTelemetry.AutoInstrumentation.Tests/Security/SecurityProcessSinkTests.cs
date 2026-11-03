// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityProcessSinkTests
{
    [Fact]
    public void ExecutableIdentityIsReportedWithoutExportingItsPath()
    {
        using var scope = SecurityRequestContext.Begin("app-process");
        var input = new string("/missing/private-marker".ToCharArray());
        scope.Taint.Source(input, "http.request.parameter", "id", "request.query");
        SecurityProcessSink.Observe(new ProcessStartInfo(input) { UseShellExecute = false });
        var observation = Assert.Single(scope.Findings.Close());
        Assert.Equal("command_execution", observation.Rule);
        Assert.Equal("executable", observation.Sink.Role);
        Assert.DoesNotContain("private-marker", FindingEvent.Encode(observation, true)!, StringComparison.Ordinal);
    }

    [Fact]
    public void ShellMetacharactersInAnArgumentAreNotAutomaticallyShellInjection()
    {
        using var scope = SecurityRequestContext.Begin("app-process");
        var input = new string("value; private-marker".ToCharArray());
        scope.Taint.Source(input, "http.request.parameter", "id", "request.query");
        var info = new ProcessStartInfo("/bin/echo") { UseShellExecute = false, Arguments = input };
        SecurityProcessSink.Observe(info);
        var observation = Assert.Single(scope.Findings.Close());
        Assert.Equal("command_execution", observation.Rule);
        Assert.Equal("argument", observation.Sink.Role);
        Assert.DoesNotContain("private-marker", FindingEvent.Encode(observation, true)!, StringComparison.Ordinal);
    }

    [Fact]
    public void WindowsShellNamesRespectPlatformCaseRules()
    {
        using var scope = SecurityRequestContext.Begin("app-process");
        var script = new string("/c echo private-marker".ToCharArray());
        scope.Taint.Source(script, "http.request.parameter", "id", "request.query");
        SecurityProcessSink.Observe(new ProcessStartInfo("CMD.EXE") { UseShellExecute = false, Arguments = script });
        var observation = Assert.Single(scope.Findings.Close());
        var windows = Environment.OSVersion.Platform == PlatformID.Win32NT;
        Assert.Equal(windows ? "command_injection" : "command_execution", observation.Rule);
        Assert.Equal(windows ? "shell_script" : "argument", observation.Sink.Role);
        Assert.DoesNotContain("private-marker", FindingEvent.Encode(observation, true)!, StringComparison.Ordinal);
    }

    [Fact]
    public void AModeledShellCommandHasUnknownAttackEvidence()
    {
        using var scope = SecurityRequestContext.Begin("app-process");
        var input = new string("printf private-marker".ToCharArray());
        scope.Taint.Source(input, "http.request.parameter", "id", "request.query");
        var script = string.Concat("-c ", input);
        scope.Taint.Concat(script, ["-c ", input]);
        var info = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, Arguments = script };
        SecurityProcessSink.Observe(info);
        var observation = Assert.Single(scope.Findings.Close());
        Assert.Equal("command_injection", observation.Rule);
        Assert.Equal("shell_script", observation.Sink.Role);
        Assert.Equal(RequestFindings.EvidenceStatus.Unknown, observation.Evidence.Status);
    }
}
