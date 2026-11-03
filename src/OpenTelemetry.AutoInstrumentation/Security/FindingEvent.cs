// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Globalization;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class FindingEvent
{
    public static string? Encode(RequestFindings.Observation observation, bool complete, int maxBytes = 65536, RequestDetails? request = null)
    {
        var record = new Record
        {
            InstanceId = SecurityIdentity.InstanceId,
            ObservedAt = observation.ObservedAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            FindingId = observation.FindingId,
            OccurrenceId = observation.OccurrenceId,
            Rule = observation.Rule,
            CollectionComplete = complete,
            TraceId = observation.Trace?.TraceId.ToHexString(),
            ServerSpanId = observation.Trace is { } trace && trace.ServerSpanId != default ? trace.ServerSpanId.ToHexString() : null,
            CurrentSpanId = observation.Trace is { } current && current.CurrentSpanId != current.ServerSpanId ? current.CurrentSpanId.ToHexString() : null,
            Request = CreateRequest(request),
            Sink = new SinkData
            {
                Function = observation.Sink.Function,
                Role = observation.Sink.Role,
                Location = observation.Sink.Location,
                Operation = NonEmpty(observation.Sink.Operation),
                PathRole = NonEmpty(observation.Sink.PathRole),
                InputPart = NonEmpty(observation.Sink.InputPart),
            },
            AttackEvidence = new EvidenceData
            {
                Status = observation.Evidence.Status switch
                {
                    RequestFindings.EvidenceStatus.Suspected => "suspected",
                    RequestFindings.EvidenceStatus.NoEvidence => "no_evidence",
                    _ => "unknown",
                },
                Reason = observation.Evidence.Reason,
            },
            Sources = observation.Ranges.Select(range => range.Source).GroupBy(source => source.Id, StringComparer.Ordinal).Select(group => group.First()).Select(source => new SourceData
            {
                Id = source.Id,
                Type = source.Type,
                Name = source.Name,
                Location = source.Location,
                ValueLength = source.ValueLength,
            }).ToArray(),
            Ranges = observation.Ranges.Select(range => new RangeData { SourceId = range.Source.Id, Start = range.Start, End = range.End }).ToArray(),
        };
        var json = Serialize(record);
        if (Encoding.UTF8.GetByteCount(json) <= maxBytes)
        {
            return json;
        }

        record.Sources = null;
        record.Ranges = null;
        record.EvidenceSampled = false;
        record.EvidenceSampleReason = "record_byte_limit";
        record.Truncated = true;
        record.TruncationReason = "record_byte_limit";
        json = Serialize(record);
        return Encoding.UTF8.GetByteCount(json) <= maxBytes ? json : null;
    }

    private static RequestData? CreateRequest(RequestDetails? request)
    {
        if (request is null || (string.IsNullOrEmpty(request.Method) && string.IsNullOrEmpty(request.Route) && !request.StatusCode.HasValue && string.IsNullOrEmpty(request.ErrorType)))
        {
            return null;
        }

        return new RequestData
        {
            Method = NonEmpty(request.Method ?? string.Empty),
            Route = NonEmpty(request.Route ?? string.Empty),
            StatusCode = request.StatusCode,
            ErrorType = NonEmpty(request.ErrorType ?? string.Empty),
        };
    }

    private static string? NonEmpty(string value)
    {
        return string.IsNullOrEmpty(value) ? null : value;
    }

    private static string Serialize(Record record)
    {
        using var stream = new MemoryStream();
        new DataContractJsonSerializer(typeof(Record)).WriteObject(stream, record);
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    [DataContract]
    private sealed class Record
    {
        [DataMember(Name = "request", EmitDefaultValue = false)]
        public RequestData? Request { get; set; }

        [DataMember(Name = "trace_id", EmitDefaultValue = false)]
        public string? TraceId { get; set; }

        [DataMember(Name = "server_span_id", EmitDefaultValue = false)]
        public string? ServerSpanId { get; set; }

        [DataMember(Name = "current_span_id", EmitDefaultValue = false)]
        public string? CurrentSpanId { get; set; }

        [DataMember(Name = "schema_version")]
        public int SchemaVersion { get; set; } = 2;

        [DataMember(Name = "source")]
        public string Source { get; set; } = "beacon_security";

        [DataMember(Name = "event_name")]
        public string EventName { get; set; } = "beacon.security.finding";

        [DataMember(Name = "instance_id")]
        public string InstanceId { get; set; } = string.Empty;

        [DataMember(Name = "observed_at")]
        public string ObservedAt { get; set; } = string.Empty;

        [DataMember(Name = "finding_id")]
        public string FindingId { get; set; } = string.Empty;

        [DataMember(Name = "occurrence_id")]
        public string OccurrenceId { get; set; } = string.Empty;

        [DataMember(Name = "fingerprint_version")]
        public int FingerprintVersion { get; set; } = 1;

        [DataMember(Name = "rule")]
        public string Rule { get; set; } = string.Empty;

        [DataMember(Name = "sink")]
        public SinkData Sink { get; set; } = new();

        [DataMember(Name = "attack_evidence")]
        public EvidenceData AttackEvidence { get; set; } = new();

        [DataMember(Name = "evidence_sampled")]
        public bool EvidenceSampled { get; set; } = true;

        [DataMember(Name = "collection_complete")]
        public bool CollectionComplete { get; set; }

        [DataMember(Name = "precision")]
        public string Precision { get; set; } = "exact";

        [DataMember(Name = "coverage_gaps")]
        public string[] CoverageGaps { get; set; } = ["query_sources_and_string_concat_only"];

        [DataMember(Name = "sources", EmitDefaultValue = false)]
        public SourceData[]? Sources { get; set; }

        [DataMember(Name = "ranges", EmitDefaultValue = false)]
        public RangeData[]? Ranges { get; set; }

        [DataMember(Name = "evidence_sample_reason", EmitDefaultValue = false)]
        public string? EvidenceSampleReason { get; set; }

        [DataMember(Name = "truncated", EmitDefaultValue = false)]
        public bool? Truncated { get; set; }

        [DataMember(Name = "truncation_reason", EmitDefaultValue = false)]
        public string? TruncationReason { get; set; }
    }

    [DataContract]
    private sealed class RequestData
    {
        [DataMember(Name = "method", EmitDefaultValue = false)]
        public string? Method { get; set; }

        [DataMember(Name = "route", EmitDefaultValue = false)]
        public string? Route { get; set; }

        [DataMember(Name = "status_code", EmitDefaultValue = false)]
        public int? StatusCode { get; set; }

        [DataMember(Name = "error_type", EmitDefaultValue = false)]
        public string? ErrorType { get; set; }
    }

    [DataContract]
    private sealed class SinkData
    {
        [DataMember(Name = "function")]
        public string Function { get; set; } = string.Empty;

        [DataMember(Name = "role")]
        public string Role { get; set; } = string.Empty;

        [DataMember(Name = "location")]
        public string Location { get; set; } = string.Empty;

        [DataMember(Name = "operation", EmitDefaultValue = false)]
        public string? Operation { get; set; }

        [DataMember(Name = "path_role", EmitDefaultValue = false)]
        public string? PathRole { get; set; }

        [DataMember(Name = "input_part", EmitDefaultValue = false)]
        public string? InputPart { get; set; }
    }

    [DataContract]
    private sealed class EvidenceData
    {
        [DataMember(Name = "status")]
        public string Status { get; set; } = string.Empty;

        [DataMember(Name = "reason")]
        public string Reason { get; set; } = string.Empty;
    }

    [DataContract]
    private sealed class SourceData
    {
        [DataMember(Name = "id")]
        public string Id { get; set; } = string.Empty;

        [DataMember(Name = "type")]
        public string Type { get; set; } = string.Empty;

        [DataMember(Name = "name")]
        public string Name { get; set; } = string.Empty;

        [DataMember(Name = "location")]
        public string Location { get; set; } = string.Empty;

        [DataMember(Name = "value_type")]
        public string ValueType { get; set; } = "string";

        [DataMember(Name = "value_length")]
        public int ValueLength { get; set; }
    }

    [DataContract]
    private sealed class RangeData
    {
        [DataMember(Name = "source_id")]
        public string SourceId { get; set; } = string.Empty;

        [DataMember(Name = "start")]
        public int Start { get; set; }

        [DataMember(Name = "end")]
        public int End { get; set; }

        [DataMember(Name = "exact")]
        public bool Exact { get; set; } = true;

        [DataMember(Name = "unit")]
        public string Unit { get; set; } = "utf16_code_unit";
    }
}
