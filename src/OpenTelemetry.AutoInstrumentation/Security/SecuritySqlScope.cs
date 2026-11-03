// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Data;
using System.Diagnostics;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class SecuritySqlScope : IDisposable
{
    private static readonly AsyncLocal<SecuritySqlScope?> Ambient = new();

    [ThreadStatic]
    private static bool _inspecting;
    private SecuritySqlScope? _parent;
    private object? _command;
    private SecurityRequestContext? _request;
    private int _closed;

    private SecuritySqlScope(object command, SecurityRequestContext request)
    {
        _command = command;
        _request = request;
        _parent = Ambient.Value;
        Ambient.Value = this;
    }

    public static SecuritySqlScope? Begin(object command, string methodName)
    {
        if (_inspecting)
        {
            return null;
        }

        try
        {
            _inspecting = true;
            var request = SecurityRequestContext.Current;
            if (request is null || command is not IDbCommand dbCommand || dbCommand.CommandType != CommandType.Text)
            {
                return null;
            }

            var parent = Ambient.Value;
            if (parent is not null && Volatile.Read(ref parent._closed) == 0 && ReferenceEquals(parent._command, command) && ReferenceEquals(parent._request, request))
            {
                return null;
            }

            var ranges = request.Taint.AtSink(dbCommand.CommandText);
            if (ranges.Length == 0)
            {
                return null;
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

            request.Findings.Observe(
                "sql_injection",
                new RequestFindings.Sink(command.GetType().FullName + "." + methodName, "sql_template", location),
                ranges,
                new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, "sql_dialect_analysis_unavailable"));
            return new SecuritySqlScope(command, request);
        }
        catch (Exception)
        {
            SecurityRequestContext.Current?.Taint.MarkIncomplete();
            return null;
        }
        finally
        {
            _inspecting = false;
        }
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _closed, 1);
        if (ReferenceEquals(Ambient.Value, this))
        {
            Ambient.Value = _parent;
        }

        _command = null;
        _request = null;
        _parent = null;
    }
}
