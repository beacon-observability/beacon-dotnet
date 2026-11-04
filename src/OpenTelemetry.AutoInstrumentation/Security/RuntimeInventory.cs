// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class RuntimeInventory
{
    public static Dependency[] Collect(IEnumerable<Assembly> assemblies, int capacity)
    {
        var dependencies = new SortedDictionary<string, Dependency>(StringComparer.Ordinal);
        foreach (var assembly in assemblies)
        {
            if (assembly.IsDynamic)
            {
                continue;
            }

            // Do not parse artifact files on application threads or invent package versions.
            // Assembly versions describe loaded CLR assemblies, not NuGet package identities.
            var identity = assembly.GetName();
            if (string.IsNullOrEmpty(identity.Name) || identity.Version is null)
            {
                continue;
            }

            var version = identity.Version.ToString();
            dependencies[identity.Name + "\0" + version] = new Dependency(identity.Name, version);
            if (dependencies.Count > capacity)
            {
                throw new InvalidOperationException("Runtime inventory capacity exceeded.");
            }
        }

        return dependencies.Values.ToArray();
    }

    public static string[] Encode(Dependency[] dependencies, string instanceId, DateTime observedAt, DateTime startedAt, long uptimeMilliseconds, int maxBytes)
    {
        Inventory Create(Dependency[] entries, int? index = null, int? count = null) => new()
        {
            InstanceId = instanceId,
            ObservedAt = observedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            StartedAt = startedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            UptimeMilliseconds = Math.Max(0, uptimeMilliseconds),
            Dependencies = entries,
            PartIndex = index,
            PartCount = count,
        };

        var whole = Serialize(Create(dependencies));
        if (Encoding.UTF8.GetByteCount(whole) <= maxBytes)
        {
            return [whole];
        }

        // Reserve maximum-width part metadata while packing. Encode every part before
        // returning any, so an unrepresentable entry cannot publish an incomplete list.
        var parts = new List<Dependency[]>();
        var current = new List<Dependency>();
        foreach (var dependency in dependencies)
        {
            current.Add(dependency);
            if (Encoding.UTF8.GetByteCount(Serialize(Create(current.ToArray(), int.MaxValue, int.MaxValue))) <= maxBytes)
            {
                continue;
            }

            current.RemoveAt(current.Count - 1);
            if (current.Count == 0)
            {
                throw new InvalidOperationException("Runtime inventory entry exceeds the record byte budget.");
            }

            parts.Add(current.ToArray());
            current.Clear();
            current.Add(dependency);
            if (Encoding.UTF8.GetByteCount(Serialize(Create(current.ToArray(), int.MaxValue, int.MaxValue))) > maxBytes)
            {
                throw new InvalidOperationException("Runtime inventory entry exceeds the record byte budget.");
            }
        }

        if (current.Count > 0)
        {
            parts.Add(current.ToArray());
        }

        if (parts.Count < 2)
        {
            throw new InvalidOperationException("Runtime inventory envelope exceeds the record byte budget.");
        }

        return parts.Select((part, index) => Serialize(Create(part, index, parts.Count))).ToArray();
    }

    private static string Serialize(Inventory inventory)
    {
        using var stream = new MemoryStream();
        new DataContractJsonSerializer(typeof(Inventory)).WriteObject(stream, inventory);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    [DataContract]
    internal sealed class Dependency(string name, string version)
    {
        [DataMember(Name = "name")]
        public string Name { get; private set; } = name;

        [DataMember(Name = "version")]
        public string Version { get; private set; } = version;
    }

    [DataContract]
    private sealed class Inventory
    {
        [DataMember(Name = "schema_version")]
        public int SchemaVersion { get; set; } = 2;

        [DataMember(Name = "source")]
        public string Source { get; set; } = "beacon_security_sbom";

        [DataMember(Name = "event_name")]
        public string EventName { get; set; } = "beacon.security.sbom.inventory";

        [DataMember(Name = "instance_id")]
        public string InstanceId { get; set; } = string.Empty;

        [DataMember(Name = "observed_at")]
        public string ObservedAt { get; set; } = string.Empty;

        [DataMember(Name = "started_at")]
        public string StartedAt { get; set; } = string.Empty;

        [DataMember(Name = "uptime_ms")]
        public long UptimeMilliseconds { get; set; }

        [DataMember(Name = "dependencies")]
        public Dependency[] Dependencies { get; set; } = [];

        [DataMember(Name = "part_index", EmitDefaultValue = false)]
        public int? PartIndex { get; set; }

        [DataMember(Name = "part_count", EmitDefaultValue = false)]
        public int? PartCount { get; set; }
    }
}
