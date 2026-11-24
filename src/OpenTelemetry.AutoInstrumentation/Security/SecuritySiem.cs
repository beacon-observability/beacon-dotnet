// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using OpenTelemetry.AutoInstrumentation.Configurations;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecuritySiem
{
    private static readonly Lazy<Dictionary<string, string>> Resource = new(() =>
    {
        var resource = Instrumentation.LoggerProvider?.GetResource() ?? ResourceConfigurator.CreateResourceBuilder(Instrumentation.ResourceSettings.Value).Build();
        return resource.Attributes.Where(pair => pair.Value is string).ToDictionary(pair => pair.Key, pair => (string)pair.Value, StringComparer.Ordinal);
    });

    public static int WireBytes(string raw) => Encoding.UTF8.GetByteCount(Encode(raw, Resource.Value));

    public static string Project(string raw) => Encode(raw, Resource.Value);

    public static string Encode(string raw, IDictionary<string, string>? resource = null, IDictionary<string, string>? context = null)
    {
        using var reader = JsonReaderWriterFactory.CreateJsonReader(Encoding.UTF8.GetBytes(raw), XmlDictionaryReaderQuotas.Max);
        var body = XElement.Load(reader);
        string Required(string key) => body.Element(key)?.Value ?? throw new SerializationException("Missing Security projection field: " + key);
        string Value(IDictionary<string, string>? map, string key) => map is not null && map.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : string.Empty;
        var inventory = Required("event_name") == "beacon.security.sbom.inventory";
        var source = inventory ? "beacon_security_sbom" : "beacon_security";
        if (Required("schema_version") != "2" || Required("source") != source ||
            (!inventory && Required("event_name") != "beacon.security.finding") ||
            body.Element("server_span_id") is not null || body.Element("current_span_id") is not null)
        {
            throw new SerializationException("Unsupported Security event.");
        }

        var tenant = Value(context, "tenant_id");
        tenant = tenant.Length > 0 ? tenant : Value(resource, "tenant.id");
        var ip = Value(context, "client_ip");
        var record = new Envelope
        {
            Time = Required("observed_at"),
            EventId = inventory ? InventoryId(source, Required("event_name"), Required("instance_id"), Required("observed_at"), body.Element("part_index")?.Value ?? "0") : Required("occurrence_id"),
            EventClass = inventory ? "software_inventory_info" : "security_finding",
            Source = source,
            Service = Value(resource, "service.name"),
            TenantId = tenant.Length > 0 ? tenant : "default",
            Actor = inventory ? string.Empty : Value(context, "actor"),
            Ip = !inventory && IsClientIp(ip) ? ip : string.Empty,
            Action = inventory ? "inventory_snapshot" : Required("rule"),
            Target = Required(inventory ? "instance_id" : "finding_id"),
            TargetType = inventory ? "process" : "finding",
            Outcome = inventory ? "success" : "unknown",
            Message = raw,
            InstanceId = Required("instance_id"),
            TraceId = body.Element("trace_id")?.Value,
            SpanId = body.Element("span_id")?.Value,
            TraceFlags = body.Element("trace_flags") is { } flags ? int.Parse(flags.Value, CultureInfo.InvariantCulture) : null,
        };
        using var stream = new MemoryStream();
        new DataContractJsonSerializer(typeof(Envelope)).WriteObject(stream, record);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static bool IsClientIp(string ip)
    {
        if (!ip.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F') or ':' or '.') || !IPAddress.TryParse(ip, out var address))
        {
            return false;
        }

        // IPAddress also accepts abbreviated/legacy IPv4 spellings; the profile does not.
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || string.Equals(ip, address.ToString(), StringComparison.Ordinal);
    }

    private static string InventoryId(params string[] values)
    {
        // Hash compact UTF-8 JSON, with literal Unicode and no optional slash escaping.
        var json = "[" + string.Join(",", values.Select(Quote)) + "]";
#if NETFRAMEWORK
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(json));
#else
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
#endif
        const string alphabet = "0123456789abcdef";
        var hex = new char[bytes.Length * 2];
        for (var index = 0; index < bytes.Length; index++)
        {
            hex[index * 2] = alphabet[bytes[index] >> 4];
            hex[(index * 2) + 1] = alphabet[bytes[index] & 15];
        }

        return "inventory-" + new string(hex);
    }

    private static string Quote(string value)
    {
        var result = new StringBuilder("\"");
        foreach (var character in value)
        {
            result.Append(character switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                '\b' => "\\b",
                '\f' => "\\f",
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                < ' ' => "\\u" + ((int)character).ToString("x4", CultureInfo.InvariantCulture),
                _ => character.ToString(),
            });
        }

        return result.Append('"').ToString();
    }

    [DataContract]
    private sealed class Envelope
    {
        [DataMember(Name = "time")]
        public string Time { get; set; } = string.Empty;

        [DataMember(Name = "event_id")]
        public string EventId { get; set; } = string.Empty;

        [DataMember(Name = "event_class")]
        public string EventClass { get; set; } = string.Empty;

        [DataMember(Name = "source")]
        public string Source { get; set; } = string.Empty;

        [DataMember(Name = "service")]
        public string Service { get; set; } = string.Empty;

        [DataMember(Name = "tenant_id")]
        public string TenantId { get; set; } = string.Empty;

        [DataMember(Name = "actor")]
        public string Actor { get; set; } = string.Empty;

        [DataMember(Name = "ip")]
        public string Ip { get; set; } = string.Empty;

        [DataMember(Name = "action")]
        public string Action { get; set; } = string.Empty;

        [DataMember(Name = "target")]
        public string Target { get; set; } = string.Empty;

        [DataMember(Name = "target_type")]
        public string TargetType { get; set; } = string.Empty;

        [DataMember(Name = "outcome")]
        public string Outcome { get; set; } = string.Empty;

        [DataMember(Name = "message")]
        public string Message { get; set; } = string.Empty;

        [DataMember(Name = "instance_id")]
        public string InstanceId { get; set; } = string.Empty;

        [DataMember(Name = "trace_id", EmitDefaultValue = false)]
        public string? TraceId { get; set; }

        [DataMember(Name = "span_id", EmitDefaultValue = false)]
        public string? SpanId { get; set; }

        [DataMember(Name = "trace_flags", EmitDefaultValue = false)]
        public int? TraceFlags { get; set; }

        [DataMember(Name = "status")]
        public string Status { get; set; } = "info";

        [DataMember(Name = "severity")]
        public string Severity { get; set; } = "informational";
    }
}
