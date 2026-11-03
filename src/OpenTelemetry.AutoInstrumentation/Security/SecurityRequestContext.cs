// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class SecurityRequestContext : IDisposable
{
    private static readonly AsyncLocal<SecurityRequestContext?> Ambient = new();
    private readonly SecurityRequestContext? _parent;
    private int _closed;

    private SecurityRequestContext(string applicationId)
    {
        _parent = Current;
        Taint = new RequestTaint();
        Findings = new RequestFindings(applicationId);
        Ambient.Value = this;
    }

    public static SecurityRequestContext? Current
    {
        get
        {
            var context = Ambient.Value;
            return context is not null && Volatile.Read(ref context._closed) == 0 ? context : null;
        }
    }

    public RequestTaint Taint { get; }

    public RequestFindings Findings { get; }

    public Func<Exception?, RequestDetails?>? RequestDetailsProvider { get; set; }

    public static SecurityRequestContext Begin(string applicationId)
    {
        return new SecurityRequestContext(applicationId);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _closed, 1) == 0)
        {
            Taint.Close();
            Findings.Close();
            RequestDetailsProvider = null;
        }

        if (ReferenceEquals(Ambient.Value, this))
        {
            Ambient.Value = _parent;
        }
    }
}
