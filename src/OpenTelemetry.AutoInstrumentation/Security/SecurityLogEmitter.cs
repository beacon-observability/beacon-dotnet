// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Reflection;
using OpenTelemetry.Logs;

namespace OpenTelemetry.AutoInstrumentation.Security;

// The distribution currently uses the SDK's internal Logs API, as do the log bridges.
// Keep reflection here until the upstream public Logs API is available.
internal sealed class SecurityLogEmitter
{
    private readonly object _logger;
    private readonly Type _dataType;
    private readonly Type _attributesType;
    private readonly MethodInfo _emit;

    public SecurityLogEmitter(LoggerProvider provider)
    {
        _logger = typeof(LoggerProvider).GetMethod("GetLogger", BindingFlags.Instance | BindingFlags.NonPublic, null, [typeof(string), typeof(string)], null)!
            .Invoke(provider, ["io.beacon.security", typeof(SecurityLogEmitter).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion])!;
        _dataType = typeof(LoggerProvider).Assembly.GetType("OpenTelemetry.Logs.LogRecordData", true)!;
        _attributesType = typeof(LoggerProvider).Assembly.GetType("OpenTelemetry.Logs.LogRecordAttributeList", true)!;
        _emit = _logger.GetType().GetMethod("EmitLog", BindingFlags.Instance | BindingFlags.Public, null, [_dataType.MakeByRefType(), _attributesType.MakeByRefType()], null)!;
    }

    public void EmitInventory(string body)
    {
        Emit(body, "beacon.security.sbom.inventory", "beacon_security_sbom");
    }

    public void EmitFinding(string body, FindingTrace? trace = null)
    {
        Emit(body, "beacon.security.finding", "beacon_security", trace);
    }

    private void Emit(string body, string eventName, string source, FindingTrace? trace = null)
    {
        var data = Activator.CreateInstance(_dataType)!;
        _dataType.GetProperty("Body")!.SetValue(data, body);
        _dataType.GetProperty("EventName")!.SetValue(data, eventName);
        _dataType.GetProperty("Timestamp")!.SetValue(data, DateTime.UtcNow);
        _dataType.GetProperty("ObservedTimestamp")!.SetValue(data, DateTime.UtcNow);
        _dataType.GetProperty("SeverityText")!.SetValue(data, "INFO");
        if (trace is not null)
        {
            _dataType.GetProperty("TraceId")!.SetValue(data, trace.TraceId);
            _dataType.GetProperty("SpanId")!.SetValue(data, trace.CurrentSpanId);
            _dataType.GetProperty("TraceFlags")!.SetValue(data, trace.Flags);
        }

        var severityType = Nullable.GetUnderlyingType(_dataType.GetProperty("Severity")!.PropertyType)!;
        _dataType.GetProperty("Severity")!.SetValue(data, Enum.ToObject(severityType, 9));
        var attributes = Activator.CreateInstance(_attributesType)!;
        var add = _attributesType.GetMethod("Add", [typeof(string), typeof(object)])!;
        add.Invoke(attributes, ["event.name", eventName]);
        add.Invoke(attributes, ["source", source]);
        _emit.Invoke(_logger, [data, attributes]);
    }
}
