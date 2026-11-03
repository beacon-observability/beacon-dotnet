// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecuritySinks
{
    public static void ReadFile(string path)
    {
        try
        {
            var scope = SecurityRequestContext.Current;
            if (scope is null)
            {
                return;
            }

            var ranges = scope.Taint.AtSink(path);
            if (ranges.Length == 0)
            {
                return;
            }

            var location = string.Empty;
            foreach (var frame in new StackTrace(1, false).GetFrames())
            {
                var method = frame.GetMethod();
                var type = method?.DeclaringType;
                var assemblyName = type?.Assembly.GetName().Name;
                if (type is null || assemblyName is null || assemblyName.StartsWith("System", StringComparison.Ordinal) || assemblyName.StartsWith("Microsoft", StringComparison.Ordinal) || assemblyName.StartsWith("OpenTelemetry", StringComparison.Ordinal))
                {
                    continue;
                }

                location = type.FullName + "#" + method!.Name;
                break;
            }

            scope.Findings.Observe(
                "path_traversal",
                new RequestFindings.Sink("System.IO.File.ReadAllText", "file_path", location, "read", "source"),
                ranges,
                new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, "path_boundary_policy_unavailable"));
        }
        catch (Exception)
        {
            // Observation must not alter file I/O behavior, including its exceptions.
        }
    }
}
