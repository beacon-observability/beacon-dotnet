// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace OpenTelemetry.AutoInstrumentation.Security;

// Keep the logical event for diagnostics; move only transport metadata at export.
internal sealed class SecurityLogRecord(string body, DateTime timestamp, string eventId)
{
    public string Body { get; } = body;

    public DateTime Timestamp { get; } = timestamp;

    public string EventId { get; } = eventId;

    public static SecurityLogRecord Bind(string json)
    {
        using var reader = JsonReaderWriterFactory.CreateJsonReader(Encoding.UTF8.GetBytes(json), XmlDictionaryReaderQuotas.Max);
        var root = XElement.Load(reader);
        string Field(string name) => root.Element(name)?.Value ?? throw new InvalidOperationException("Missing Security field: " + name);
        var observedAt = Field("observed_at");
        var timestamp = DateTime.ParseExact(observedAt, ["yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal);
        var nanos = checked((timestamp.Ticks - 621355968000000000L) * 100);
        if (nanos <= 0)
        {
            throw new InvalidOperationException("Security event time outside receiver range.");
        }

        var inventory = Field("event_name") == "beacon.security.sbom.inventory";
        var eventId = inventory ? InventoryId([Field("source"), Field("event_name"), Field("instance_id"), observedAt, root.Element("part_index")?.Value ?? "0"]) : Field("occurrence_id");
        root.Element("observed_at")!.Remove();
        root.Element("occurrence_id")?.Remove();
        using var stream = new MemoryStream();
        using (var writer = JsonReaderWriterFactory.CreateJsonWriter(stream, Encoding.UTF8, false))
        {
            WriteElement(writer, root);
            writer.Flush();
        }

        return new SecurityLogRecord(Encoding.UTF8.GetString(stream.ToArray()), timestamp, eventId);
    }

    private static void WriteElement(XmlWriter writer, XElement element)
    {
        writer.WriteStartElement(element.Name.LocalName);
        foreach (var attribute in element.Attributes())
        {
            writer.WriteAttributeString(attribute.Name.LocalName, attribute.Value);
        }

        var type = (string?)element.Attribute("type");
        if (type is "object" or "array")
        {
            foreach (var child in element.Elements())
            {
                WriteElement(writer, child);
            }
        }
        else if (type != "null")
        {
            writer.WriteString(element.Value);
        }

        writer.WriteEndElement();
    }

    private static string InventoryId(string[] fields)
    {
        // JSON's required escapes only; do not escape literal Unicode or slashes.
        var json = "[" + string.Join(",", fields.Select(value => "\"" + Escape(value) + "\"")) + "]";
        using var hash = SHA256.Create();
        return "inventory-" + BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(json))).Replace("-", string.Empty).ToLowerInvariant();
    }

    private static string Escape(string value)
    {
        var result = new StringBuilder();
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

        return result.ToString();
    }
}
