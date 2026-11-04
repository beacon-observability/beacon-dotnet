// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class RequestFindings(string applicationId, int capacity = 128)
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Observation> _observations = new(StringComparer.Ordinal);
    private bool _complete = true;
    private bool _closed;

    internal enum EvidenceStatus
    {
        NoEvidence,
        Unknown,
        Suspected,
    }

    public bool Complete
    {
        get
        {
            lock (_gate)
            {
                return _complete;
            }
        }
    }

    public void Observe(string rule, Sink sink, RequestTaint.TaintedRange[] ranges, AttackEvidence evidence)
    {
        if (ranges.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (_closed)
            {
                return;
            }

            if (ranges.Length > 128 || evidence.Reason.Length > 256)
            {
                _complete = false;
                return;
            }

            var findingId = FindingFingerprint.Compute(
                applicationId,
                "dotnet",
                rule,
                sink.Role,
                sink.Function,
                sink.Location,
                sink.Operation,
                sink.PathRole,
                sink.InputPart,
                ranges.Select(range => range.Source.Type + "|" + range.Source.Name));
            if (_observations.TryGetValue(findingId, out var existing))
            {
                // Evidence ordering belongs to this occurrence only. It must never
                // overwrite the classification of a previous or concurrent request.
                if (evidence.Status > existing.Evidence.Status)
                {
                    _observations[findingId] = new Observation(existing.FindingId, existing.OccurrenceId, existing.Rule, existing.Sink, ranges.ToArray(), evidence, existing.ObservedAt, existing.Trace);
                }

                return;
            }

            if (_observations.Count >= capacity)
            {
                _complete = false;
                return;
            }

            _observations.Add(findingId, new Observation(findingId, Guid.NewGuid().ToString("D"), rule, sink, ranges.ToArray(), evidence, trace: FindingTrace.Capture()));
        }
    }

    public Observation[] Close()
    {
        lock (_gate)
        {
            if (_closed)
            {
                return [];
            }

            _closed = true;
            var result = _observations.Values.ToArray();
            _observations.Clear();
            return result;
        }
    }

    internal sealed class AttackEvidence(EvidenceStatus status, string reason)
    {
        public EvidenceStatus Status { get; } = status;

        public string Reason { get; } = reason;
    }

    internal sealed class Sink(string function, string role, string location, string operation = "", string pathRole = "", string inputPart = "")
    {
        public string Function { get; } = function;

        public string Role { get; } = role;

        public string Location { get; } = location;

        public string Operation { get; } = operation;

        public string PathRole { get; } = pathRole;

        public string InputPart { get; } = inputPart;
    }

    internal sealed class Observation(string findingId, string occurrenceId, string rule, Sink sink, RequestTaint.TaintedRange[] ranges, AttackEvidence evidence, DateTime? observedAt = null, FindingTrace? trace = null)
    {
        public string FindingId { get; } = findingId;

        public string OccurrenceId { get; } = occurrenceId;

        public string Rule { get; } = rule;

        public Sink Sink { get; } = sink;

        public RequestTaint.TaintedRange[] Ranges { get; } = ranges;

        public AttackEvidence Evidence { get; } = evidence;

        public DateTime ObservedAt { get; } = observedAt ?? DateTime.UtcNow;

        public FindingTrace? Trace { get; } = trace;
    }
}
