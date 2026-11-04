// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Collections;
using OpenTelemetry.AutoInstrumentation.Configurations;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class HttpRequestTracking
{
    private static readonly Lazy<string> ApplicationId = new(() =>
    {
        var attributes = ResourceConfigurator.CreateResourceBuilder(Instrumentation.ResourceSettings.Value).Build().Attributes.ToDictionary(pair => pair.Key, pair => pair.Value);
        var serviceNamespace = attributes.TryGetValue("service.namespace", out var ns) ? ns as string ?? string.Empty : string.Empty;
        var serviceName = attributes.TryGetValue("service.name", out var name) ? name as string ?? "unknown_service" : "unknown_service";
        return FindingFingerprint.ApplicationId(serviceNamespace, serviceName);
    });

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the returned scope transfers to the request CallTarget state; its async completion callback disposes it.")]
    public static SecurityRequestContext? Begin(object hostingContext)
    {
        SecurityRequestContext? scope = null;
        try
        {
            var httpContext = Property(hostingContext, "HttpContext");
            var request = httpContext is null ? null : Property(httpContext, "Request");
            if (request is null)
            {
                return null;
            }

            scope = SecurityRequestContext.Begin(ApplicationId.Value);
            scope.RequestDetailsProvider = exception => Details(httpContext!, exception);
            if (Property(request, "Query") is not IEnumerable query)
            {
                scope.Taint.MarkIncomplete();
                return scope;
            }

            var count = 0;
            foreach (var entry in query)
            {
                var name = Property(entry, "Key") as string;
                if (name is null || Property(entry, "Value") is not IEnumerable values)
                {
                    scope.Taint.MarkIncomplete();
                    continue;
                }

                foreach (var value in values)
                {
                    if (++count > 64)
                    {
                        scope.Taint.MarkIncomplete();
                        return scope;
                    }

                    if (value is string text)
                    {
                        scope.Taint.Source(text, "http.request.parameter", name, "request.query");
                    }
                }
            }

            return scope;
        }
        catch (Exception)
        {
            if (scope is not null)
            {
                scope.Taint.MarkIncomplete();
            }

            return scope;
        }
    }

    internal static RequestDetails? Details(object httpContext, Exception? exception)
    {
        try
        {
            var request = Property(httpContext, "Request");
            var response = Property(httpContext, "Response");
            var status = response is null ? null : Property(response, "StatusCode") as int?;
            if (exception is not null && response is not null && Property(response, "HasStarted") is not true)
            {
                status = null;
            }

            string? route = null;
            if (Property(httpContext, "Features") is IEnumerable features)
            {
                var inspected = 0;
                foreach (var entry in features)
                {
                    if (++inspected > 128)
                    {
                        break;
                    }

                    if (Property(entry, "Key") is not Type type || type.FullName != "Microsoft.AspNetCore.Http.Features.IEndpointFeature")
                    {
                        continue;
                    }

                    var feature = Property(entry, "Value");
                    var endpoint = feature is null ? null : type.GetProperty("Endpoint")?.GetValue(feature);
                    var pattern = endpoint is null ? null : Property(endpoint, "RoutePattern");
                    route = pattern is null ? null : Property(pattern, "RawText") as string;
                    break;
                }
            }

            return new RequestDetails(request is null ? null : Property(request, "Method") as string, route, status, exception?.GetType().FullName);
        }
        catch (Exception)
        {
            return new RequestDetails(null, null, null, exception?.GetType().FullName);
        }
    }

    private static object? Property(object target, string name)
    {
        return target.GetType().GetProperty(name)?.GetValue(target);
    }
}
