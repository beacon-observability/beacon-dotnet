// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Diagnostics;
using System.Net.Http;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecurityHttpSink
{
    private static readonly char[] AuthorityTerminators = ['/', '?', '#'];

    public static void Observe(HttpRequestMessage request)
    {
        try
        {
            var scope = SecurityRequestContext.Current;
            var uri = request.RequestUri;
            if (scope is null || uri is null || !uri.IsAbsoluteUri || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                return;
            }

            // OriginalString is used only as an identity key. Never export the URI,
            // resolve a destination, or treat string-content equality as propagation.
            var ranges = scope.Taint.AtSink(uri.OriginalString);
            if (ranges.Length == 0)
            {
                return;
            }

            var original = uri.OriginalString;
            var schemeEnd = original.IndexOf("://", StringComparison.Ordinal);
            var authorityEnd = schemeEnd < 0 ? -1 : original.IndexOfAny(AuthorityTerminators, schemeEnd + 3);
            if (schemeEnd >= 0 && authorityEnd < 0)
            {
                authorityEnd = original.Length;
            }

            var rule = "ssrf";
            var role = schemeEnd < 0 ? "destination_unknown" : "destination_address";
            var reason = "destination_policy_unavailable";
            var inputPart = string.Empty;
            if (authorityEnd >= 0)
            {
                var destinationRanges = ranges.Where(range => range.Start < authorityEnd).ToArray();
                if (destinationRanges.Length > 0)
                {
                    ranges = destinationRanges;
                }
                else
                {
                    var fragment = IndexOfDelimiter(original, '#');
                    ranges = ranges.Where(range => fragment < 0 || range.Start < fragment).ToArray();
                    if (ranges.Length == 0)
                    {
                        return;
                    }

                    var query = IndexOfDelimiter(original, '?');
                    if (fragment >= 0 && query > fragment)
                    {
                        query = -1;
                    }

                    var pathInput = ranges.Any(range => query < 0 || range.Start < query);
                    var queryInput = query >= 0 && ranges.Any(range => range.End > query);
                    rule = "http_request_input";
                    role = "path_or_query";
                    reason = "http_input_analysis_unavailable";
                    inputPart = pathInput && queryInput ? "path_or_query" : queryInput ? "query" : "path";
                }
            }

            var location = string.Empty;
            foreach (var frame in new StackTrace(1, false).GetFrames())
            {
                var method = frame.GetMethod();
                var type = method?.DeclaringType;
                var name = type?.Assembly.GetName().Name;
                if (type is null || name is null || name.StartsWith("System", StringComparison.Ordinal) || name.StartsWith("Microsoft", StringComparison.Ordinal) || name.StartsWith("OpenTelemetry", StringComparison.Ordinal))
                {
                    continue;
                }

                location = type.FullName + "#" + method!.Name;
                break;
            }

            scope.Findings.Observe(
                rule,
                new RequestFindings.Sink("System.Net.Http.HttpMessageInvoker.SendAsync", role, location, inputPart: inputPart),
                ranges,
                new RequestFindings.AttackEvidence(RequestFindings.EvidenceStatus.Unknown, reason));
        }
        catch (Exception)
        {
            SecurityRequestContext.Current?.Taint.MarkIncomplete();
        }
    }

    private static int IndexOfDelimiter(string value, char delimiter)
    {
        // URI delimiters are ASCII; preserve the same UTF-16 offsets on every TFM.
        for (var index = 0; index < value.Length; index++)
        {
            if (value[index] == delimiter)
            {
                return index;
            }
        }

        return -1;
    }
}
