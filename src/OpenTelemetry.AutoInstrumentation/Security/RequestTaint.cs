// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.CompilerServices;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Request-local object identity tracking; raw values are weak keys, never evidence fields.
/// </summary>
internal sealed class RequestTaint
{
    private readonly object _gate = new();
    private readonly ConditionalWeakTable<string, Ranges> _tainted = new();
    private readonly int _maxOperations;
    private readonly int _maxSources;
    private int _operations;
    private int _sources;
    private bool _closed;
    private bool _complete = true;

    public RequestTaint(int maxOperations = 1024, int maxSources = 64)
    {
        _maxOperations = maxOperations;
        _maxSources = maxSources;
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

    public void Source(string value, string type, string name, string location)
    {
        if (value.Length == 0)
        {
            return;
        }

        lock (_gate)
        {
            if (!CanCollect())
            {
                return;
            }

            if (_sources >= _maxSources || type.Length > 256 || name.Length > 256 || location.Length > 1024)
            {
                _complete = false;
                return;
            }

            var source = new SourceInfo("source-" + (++_sources).ToString(System.Globalization.CultureInfo.InvariantCulture), type, name, location, value.Length);
            var range = new TaintedRange(source, 0, value.Length);
            if (_tainted.TryGetValue(value, out var existing))
            {
                _tainted.Remove(value);
                _tainted.Add(value, new Ranges(existing.Values.Concat([range]).ToArray()));
            }
            else
            {
                _tainted.Add(value, new Ranges([range]));
            }
        }
    }

    public void Concat(string result, IReadOnlyList<string?> inputs)
    {
        lock (_gate)
        {
            if (!CanCollect())
            {
                return;
            }

            if (inputs.Count > 128)
            {
                _complete = false;
                return;
            }

            var ranges = new List<TaintedRange>();
            long offset = 0;
            foreach (var input in inputs)
            {
                if (input is null)
                {
                    continue;
                }

                if (offset + input.Length > result.Length || string.CompareOrdinal(input, 0, result, (int)offset, input.Length) != 0)
                {
                    _complete = false;
                    return;
                }

                if (_tainted.TryGetValue(input, out var tracked))
                {
                    foreach (var range in tracked.Values)
                    {
                        if (ranges.Count >= 128)
                        {
                            _complete = false;
                            return;
                        }

                        ranges.Add(new TaintedRange(range.Source, checked((int)offset + range.Start), checked((int)offset + range.End)));
                    }
                }

                offset += input.Length;
            }

            // Only model a known concatenation, never a coincidentally matching value.
            if (offset != result.Length)
            {
                _complete = false;
                return;
            }

            if (ranges.Count > 0)
            {
                _tainted.Remove(result);
                _tainted.Add(result, new Ranges(ranges.ToArray()));
            }
        }
    }

    public TaintedRange[] AtSink(string value)
    {
        lock (_gate)
        {
            if (_closed || !_tainted.TryGetValue(value, out var ranges))
            {
                return [];
            }

            return ranges.Values.ToArray();
        }
    }

    public void Close()
    {
        lock (_gate)
        {
            _closed = true;
            // Weak keys never keep application strings alive. Closing prevents child
            // execution contexts from continuing to observe a completed request.
        }
    }

    public void MarkIncomplete()
    {
        lock (_gate)
        {
            if (!_closed)
            {
                _complete = false;
            }
        }
    }

    private bool CanCollect()
    {
        if (_closed)
        {
            return false;
        }

        if (++_operations > _maxOperations)
        {
            _complete = false;
            return false;
        }

        return true;
    }

    internal sealed class SourceInfo(string id, string type, string name, string location, int valueLength)
    {
        public string Id { get; } = id;

        public string Type { get; } = type;

        public string Name { get; } = name;

        public string Location { get; } = location;

        public int ValueLength { get; } = valueLength;
    }

    internal sealed class TaintedRange(SourceInfo source, int start, int end)
    {
        public SourceInfo Source { get; } = source;

        public int Start { get; } = start;

        public int End { get; } = end;
    }

    private sealed class Ranges(TaintedRange[] values)
    {
        public TaintedRange[] Values { get; } = values;
    }
}
