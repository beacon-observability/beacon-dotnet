// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class RuntimeInventoryTests
{
    [Fact]
    public void CollectsUniqueLoadedAssembliesAndFailsOnCapacity()
    {
        var assembly = typeof(RuntimeInventory).Assembly;
        var dependencies = RuntimeInventory.Collect([assembly, assembly], 1);
        var dependency = Assert.Single(dependencies);
        Assert.Equal(assembly.GetName().Name, dependency.Name);
        Assert.Equal(assembly.GetName().Version!.ToString(), dependency.Version);
        Assert.Throws<InvalidOperationException>(() => RuntimeInventory.Collect([assembly], 0));
    }

    [Fact]
    public void EmptyInventoryCanClearPreviousListWithoutPartMetadata()
    {
        var document = JObject.Parse(Assert.Single(Encode([], 4096)));
        Assert.Empty((JArray)document["dependencies"]!);
        Assert.Null(document["part_index"]);
        Assert.Null(document["part_count"]);
        Assert.Equal(2, (int)document["schema_version"]!);
        Assert.Equal("beacon.security.sbom.inventory", (string?)document["event_name"]);
        Assert.Equal("beacon_security_sbom", (string?)document["source"]);
    }

    [Fact]
    public void MultipartInventoryPreservesEveryDependencyAndCollectionIdentity()
    {
        var dependencies = Enumerable.Range(0, 20).Select(index => new RuntimeInventory.Dependency("程序集" + index, "1.2.3.4")).ToArray();
        var records = Encode(dependencies, 640);
        Assert.True(records.Length > 1);
        var documents = records.Select(JObject.Parse).ToArray();
        for (var index = 0; index < records.Length; index++)
        {
            Assert.True(Encoding.UTF8.GetByteCount(records[index]) <= 640);
            Assert.Equal(index, (int)documents[index]["part_index"]!);
            Assert.Equal(records.Length, (int)documents[index]["part_count"]!);
            Assert.Equal((string?)documents[0]["observed_at"], (string?)documents[index]["observed_at"]);
            Assert.Equal((string?)documents[0]["started_at"], (string?)documents[index]["started_at"]);
            Assert.Equal((string?)documents[0]["instance_id"], (string?)documents[index]["instance_id"]);
            Assert.Equal(123L, (long)documents[index]["uptime_ms"]!);
        }

        Assert.Equal(dependencies.Select(dependency => dependency.Name), documents.SelectMany(document => document["dependencies"]!).Select(dependency => (string)dependency["name"]!));
    }

    [Fact]
    public void RejectsUnrepresentableRecordsBeforePublishingParts()
    {
        Assert.Throws<InvalidOperationException>(() => Encode([], 1));
        Assert.Throws<InvalidOperationException>(() => Encode([new RuntimeInventory.Dependency(new string('x', 4096), "1")], 640));
    }

    private static string[] Encode(RuntimeInventory.Dependency[] dependencies, int maxBytes)
    {
        return RuntimeInventory.Encode(dependencies, "01234567-89ab-cdef-0123-456789abcdef", new DateTime(2026, 11, 3, 0, 0, 1, DateTimeKind.Utc), new DateTime(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc), 123, maxBytes);
    }
}
