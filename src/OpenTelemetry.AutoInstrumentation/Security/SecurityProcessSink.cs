// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecurityProcessSink
{
    private static readonly string[] ShellNames = ["sh", "bash", "dash", "zsh", "ksh", "cmd.exe", "cmd", "powershell.exe", "pwsh", "pwsh.exe"];

    public static void Observe(ProcessStartInfo info)
    {
        var scope = SecurityRequestContext.Current;
        if (scope is null)
        {
            return;
        }

        try
        {
            var executable = info.FileName;
            var basename = Path.GetFileName(executable);
            // Windows executable lookup normally ignores case. Unix shell names
            // remain case-sensitive; this is still a name heuristic, not identity.
            var comparison = Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            var shell = IsShell(basename, comparison);
            ObserveValue(scope, executable, "command_execution", "executable", "executable_policy_unavailable");
            var arguments = info.Arguments;
            var script = shell && !info.UseShellExecute && (arguments.StartsWith("-c ", StringComparison.Ordinal) || arguments.StartsWith("-lc ", StringComparison.Ordinal) || arguments.StartsWith("/c ", StringComparison.OrdinalIgnoreCase) || arguments.StartsWith("-Command ", StringComparison.OrdinalIgnoreCase));
            ObserveValue(scope, arguments, script ? "command_injection" : "command_execution", script ? "shell_script" : "argument", script ? "shell_syntax_analysis_unavailable" : "argument_policy_unavailable");
#if NET
            var count = Math.Min(info.ArgumentList.Count, 128);
            if (info.ArgumentList.Count > count)
            {
                scope.Taint.MarkIncomplete();
            }

            for (var index = 0; index < count; index++)
            {
                var isScript = shell && !info.UseShellExecute && index == 1 && info.ArgumentList[0] is "-c" or "-lc" or "/c" or "/C" or "-Command" or "-command";
                ObserveValue(scope, info.ArgumentList[index], isScript ? "command_injection" : "command_execution", isScript ? "shell_script" : "argument", isScript ? "shell_syntax_analysis_unavailable" : "argument_policy_unavailable");
            }
#endif
        }
        catch (Exception)
        {
            scope.Taint.MarkIncomplete();
        }
    }

    private static bool IsShell(string name, StringComparison comparison)
    {
        foreach (var shell in ShellNames)
        {
            if (string.Equals(name, shell, comparison))
            {
                return true;
            }
        }

        return false;
    }

    private static void ObserveValue(SecurityRequestContext scope, string value, string rule, string role, string reason)
    {
        var ranges = scope.Taint.AtSink(value);
        if (ranges.Length == 0)
        {
            return;
        }

        var location = string.Empty;
        foreach (var frame in new StackTrace(1, false).GetFrames())
        {
            var method = frame.GetMethod();
            var type = method?.DeclaringType;
            var name = type?.Assembly.GetName().Name;
            if (type is null || name is null || name.StartsWith("System", StringComparison.Ordinal) || name.StartsWith("Microsoft", StringComparison.Ordinal) || name.StartsWith("OpenTelemetry", StringComparison.Ordinal))
            {
                continue;
            }

            location = type.FullName + "#" + method!.Name;
            break;
        }

        scope.Findings.Observe(rule, new RequestFindings.Sink("System.Diagnostics.Process.Start", role, location), ranges, new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, reason));
    }
}
