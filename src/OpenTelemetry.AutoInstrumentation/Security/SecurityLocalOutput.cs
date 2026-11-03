// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Text;
using OpenTelemetry.AutoInstrumentation.Logging;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class SecurityLocalOutput : IDisposable
{
    private static readonly IOtelLogger Logger = OtelLogging.GetLogger();
    private static readonly string[] SnapshotNames = ["inventory.jsonl", "inventory.jsonl.tmp", "finding.json", "finding.json.tmp"];
    private readonly object _gate = new();
    private readonly Queue<WorkItem> _pending = new();
#pragma warning disable CA2213 // The worker disposes the semaphore after queued work drains.
    private readonly SemaphoreSlim _available = new(0);
#pragma warning restore CA2213
    private readonly Task _worker;
    private readonly int _capacityBytes;
    private int _queuedBytes;
    private bool _closed;

    internal SecurityLocalOutput(Action<string, bool> write, int capacityBytes = 4 * 1024 * 1024)
    {
        _capacityBytes = capacityBytes;
        _worker = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    await _available.WaitAsync().ConfigureAwait(false);
                    WorkItem item;
                    lock (_gate)
                    {
                        if (_pending.Count == 0)
                        {
                            return;
                        }

                        item = _pending.Dequeue();
                    }

                    write(item.Content, item.Inventory);
                    lock (_gate)
                    {
                        // Include the in-flight write in the byte budget.
                        _queuedBytes -= item.Bytes;
                    }
                }
            }
            catch (Exception exception)
            {
                // A failed diagnostic destination must not create a retry backlog.
                Logger.Error(exception, "Beacon Security local diagnostic output stopped.");
            }
            finally
            {
                lock (_gate)
                {
                    _closed = true;
                    _pending.Clear();
                    _queuedBytes = 0;
                    _available.Dispose();
                }
            }
        });
    }

    internal Task Completion => _worker;

    public static SecurityLocalOutput? TryStart(Func<string, string?> getValue)
    {
        if (!SecurityRuntime.ReadBoolean(getValue, "BEACON_SECURITY_ENABLED", false) ||
            !SecurityRuntime.ReadBoolean(getValue, "BEACON_SECURITY_LOCAL_OUTPUT_ENABLED", false))
        {
            return null;
        }

        try
        {
            var configuredRoot = getValue("BEACON_SECURITY_OUTPUT");
            var root = string.IsNullOrWhiteSpace(configuredRoot) ? Path.Combine(Path.GetTempPath(), "beacon-security") : Path.GetFullPath(configuredRoot);
            var directory = Path.Combine(root, SecurityIdentity.InstanceId);
            var configuredEvidence = getValue("BEACON_SECURITY_EVIDENCE_FILE");
            var evidence = string.IsNullOrWhiteSpace(configuredEvidence) ? null : Path.GetFullPath(configuredEvidence);
            if (evidence is not null &&
                SnapshotNames.Any(name => string.Equals(evidence, Path.Combine(directory, name), StringComparison.OrdinalIgnoreCase)))
            {
                throw new ArgumentException("Security evidence file conflicts with a diagnostic snapshot.");
            }

            var files = new LocalFiles(directory, evidence);
            return new SecurityLocalOutput(files.Write);
        }
        catch (Exception exception)
        {
            Logger.Error(exception, "Beacon Security local diagnostic output initialization failed.");
            return null;
        }
    }

    public bool PublishFinding(string json) => Enqueue(json, false);

    public bool PublishInventory(string[] records)
    {
        long bytes = 0;
        foreach (var record in records)
        {
            bytes += Encoding.UTF8.GetByteCount(record) + 1L;
            if (bytes > _capacityBytes)
            {
                return false;
            }
        }

        return records.Length > 0 && Enqueue(string.Join("\n", records), true);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_closed)
            {
                return;
            }

            _closed = true;
            _available.Release();
        }
    }

    private bool Enqueue(string content, bool inventory)
    {
        var bytes = (long)Encoding.UTF8.GetByteCount(content) + 1;
        lock (_gate)
        {
            if (_closed || _pending.Count >= 64 || bytes > _capacityBytes - _queuedBytes)
            {
                return false;
            }

            _pending.Enqueue(new WorkItem(content, inventory, (int)bytes));
            _queuedBytes += (int)bytes;
            _available.Release();
            return true;
        }
    }

    internal sealed class LocalFiles(string directory, string? evidenceFile, int maxEvidenceBytes = 8 * 1024 * 1024)
    {
        private static readonly Encoding Utf8 = new UTF8Encoding(false);

        public void Write(string content, bool inventory)
        {
            Directory.CreateDirectory(directory);
            var destination = Path.Combine(directory, inventory ? "inventory.jsonl" : "finding.json");
            var temporary = destination + ".tmp";
            try
            {
                File.WriteAllText(temporary, content + "\n", Utf8);
                if (File.Exists(destination))
                {
                    File.Replace(temporary, destination, null);
                }
                else
                {
                    File.Move(temporary, destination);
                }
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }

            if (inventory || evidenceFile is null)
            {
                return;
            }

            var bytes = Utf8.GetByteCount(content) + 1;
            if (bytes > maxEvidenceBytes)
            {
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(evidenceFile)!);
            if (File.Exists(evidenceFile) && new FileInfo(evidenceFile).Length + bytes > maxEvidenceBytes)
            {
                var previous = evidenceFile + ".1";
                if (File.Exists(previous))
                {
                    File.Delete(previous);
                }

                File.Move(evidenceFile, previous);
            }

            using var stream = new FileStream(evidenceFile, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var writer = new StreamWriter(stream, Utf8);
            writer.Write(content);
            writer.Write('\n');
        }
    }

    private sealed class WorkItem(string content, bool inventory, int bytes)
    {
        public string Content { get; } = content;

        public bool Inventory { get; } = inventory;

        public int Bytes { get; } = bytes;
    }
}
