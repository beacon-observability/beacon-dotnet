// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityLocalOutputTests
{
    [Theory]
    [InlineData(null, null)]
    [InlineData("true", null)]
    [InlineData(null, "true")]
    [InlineData("false", "true")]
    public void FilesRequireBothOptInSwitches(string? security, string? local)
    {
        using var directory = new TestDirectory();
        var output = SecurityLocalOutput.TryStart(key => key switch
        {
            "BEACON_SECURITY_ENABLED" => security,
            "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED" => local,
            "BEACON_SECURITY_OUTPUT" => directory.Path,
            "BEACON_SECURITY_EVIDENCE_FILE" => System.IO.Path.Combine(directory.Path, "evidence.jsonl"),
            _ => null,
        });
        Assert.Null(output);
        Assert.False(Directory.Exists(directory.Path));
    }

    [Fact]
    public async Task SnapshotsReplaceCompleteRoundsAndEvidenceContainsOnlyFindings()
    {
        using var directory = new TestDirectory();
        var evidence = Path.Combine(directory.Path, "evidence.jsonl");
        using var output = SecurityLocalOutput.TryStart(key => key switch
        {
            "BEACON_SECURITY_ENABLED" or "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED" => "true",
            "BEACON_SECURITY_OUTPUT" => directory.Path,
            "BEACON_SECURITY_EVIDENCE_FILE" => evidence,
            _ => null,
        });
        Assert.NotNull(output);
        Assert.False(Directory.Exists(directory.Path));
        Assert.True(output.PublishInventory(["{\"round\":1}"]));
        Assert.True(output.PublishInventory(["{\"round\":2,\"part\":0}", "{\"round\":2,\"part\":1}"]));
        Assert.True(output.PublishFinding("{\"finding\":1}"));
        Assert.True(output.PublishFinding("{\"finding\":2}"));
        output.Dispose();
        await AwaitCompletion(output);
        var snapshotDirectory = Path.Combine(directory.Path, SecurityIdentity.InstanceId);
        Assert.Equal("{\"round\":2,\"part\":0}\n{\"round\":2,\"part\":1}\n", await ReadFileAsync(Path.Combine(snapshotDirectory, "inventory.jsonl")));
        Assert.Equal("{\"finding\":2}\n", await ReadFileAsync(Path.Combine(snapshotDirectory, "finding.json")));
        Assert.Equal("{\"finding\":1}\n{\"finding\":2}\n", await ReadFileAsync(evidence));
        Assert.Empty(Directory.GetFiles(snapshotDirectory, "*.tmp"));
        Assert.False(output.PublishFinding("{}"));
    }

    [Fact]
    public async Task InFlightWriteCountsAgainstTheByteBudgetWithoutBlockingProducers()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var writes = 0;
        using var output = new SecurityLocalOutput(
            (_, _) =>
            {
                entered.Set();
                release.Wait(TimeSpan.FromSeconds(10));
                Interlocked.Increment(ref writes);
            },
            10);
        try
        {
            Assert.True(output.PublishFinding("123456789"));
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            Assert.False(output.PublishFinding(string.Empty));
            Assert.False(output.PublishInventory(["{}"]));
            output.Dispose();
        }
        finally
        {
            release.Set();
        }

        await AwaitCompletion(output);
        Assert.Equal(1, writes);
    }

    [Fact]
    public async Task FailedDestinationClosesTheWriterWithoutPropagatingOrRetrying()
    {
        var writes = 0;
        using var output = new SecurityLocalOutput((_, _) =>
        {
            Interlocked.Increment(ref writes);
            throw new IOException("Simulated diagnostic failure.");
        });
        Assert.True(output.PublishFinding("{}"));
        await AwaitCompletion(output);
        Assert.False(output.PublishFinding("{}"));
        Assert.Equal(1, writes);
    }

    [Fact]
    public void EvidenceRotationKeepsOnlyOneBoundedPreviousFile()
    {
        using var directory = new TestDirectory();
        var evidence = Path.Combine(directory.Path, "evidence.jsonl");
        var files = new SecurityLocalOutput.LocalFiles(directory.Path, evidence, 5);
        files.Write("{}", false);
        files.Write("[]", false);
        files.Write("{}", false);
        Assert.Equal("{}\n", File.ReadAllText(evidence));
        Assert.Equal("[]\n", File.ReadAllText(evidence + ".1"));
        Assert.True(new FileInfo(evidence).Length <= 5);
        Assert.True(new FileInfo(evidence + ".1").Length <= 5);
    }

    private static async Task AwaitCompletion(SecurityLocalOutput output)
    {
        Assert.Same(output.Completion, await Task.WhenAny(output.Completion, Task.Delay(TimeSpan.FromSeconds(10))).ConfigureAwait(true));
        await output.Completion.ConfigureAwait(true);
    }

    private static async Task<string> ReadFileAsync(string path)
    {
        using var reader = File.OpenText(path);
        return await reader.ReadToEndAsync().ConfigureAwait(true);
    }

    private sealed class TestDirectory : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "beacon-security-unit-" + Guid.NewGuid().ToString("N"));

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, true);
            }
        }
    }
}
