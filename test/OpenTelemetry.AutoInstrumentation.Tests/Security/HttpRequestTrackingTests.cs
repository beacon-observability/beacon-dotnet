// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class HttpRequestTrackingTests
{
    [Fact]
    public void ExceptionBeforeResponseStartsDoesNotExportDefaultSuccessStatus()
    {
        var context = new RequestContext([]);
        var details = HttpRequestTracking.Details(context, new InvalidOperationException("private exception message"))!;
        Assert.Equal("GET", details.Method);
        Assert.Equal(typeof(InvalidOperationException).FullName, details.ErrorType);
        Assert.Null(details.StatusCode);
        Assert.Null(details.Route);
        Assert.Equal(200, HttpRequestTracking.Details(context, null)!.StatusCode);
    }

    [Fact]
    public void AsyncCompletionClosesTheScopeEvenWhenTheApplicationThrows()
    {
        var value = new string('x', 3);
        var hosting = new HostingContext(new Dictionary<string, string[]> { ["id"] = [value] });
        var state = AspNetCoreRequestIntegration.OnMethodBegin<object, HostingContext>(null!, hosting);
        using var scope = Assert.IsType<SecurityRequestContext>(state.State);
        Assert.Single(scope.Taint.AtSink(value));
        var returned = new object();
        Assert.Same(returned, AspNetCoreRequestIntegration.OnAsyncMethodEnd<object, object>(null!, returned, new InvalidOperationException("Application failure."), in state));
        Assert.Null(SecurityRequestContext.Current);
        Assert.Empty(scope.Taint.AtSink(value));
    }

    [Fact]
    public void QuerySourcesKeepOriginalStringIdentityAndCloseWithScope()
    {
        var value = new string('x', 3);
        var hosting = new HostingContext(new Dictionary<string, string[]> { ["id"] = [value] });
        using var scope = HttpRequestTracking.Begin(hosting);
        Assert.NotNull(scope);
        Assert.Same(scope, SecurityRequestContext.Current);
        var range = Assert.Single(scope.Taint.AtSink(value));
        Assert.Equal("http.request.parameter", range.Source.Type);
        Assert.Equal("id", range.Source.Name);
        Assert.Empty(scope.Taint.AtSink(new string('x', 3)));
        scope.Dispose();
        Assert.Null(SecurityRequestContext.Current);
        Assert.Null(scope.RequestDetailsProvider);
    }

    [Fact]
    public void QueryCapacityDeclaresIncompleteCollection()
    {
        var values = Enumerable.Range(0, 65).Select(index => new string((char)('a' + index), 3)).ToArray();
        using var scope = HttpRequestTracking.Begin(new HostingContext(new Dictionary<string, string[]> { ["id"] = values }));
        Assert.NotNull(scope);
        Assert.False(scope.Taint.Complete);
        Assert.Single(scope.Taint.AtSink(values[0]));
        Assert.Empty(scope.Taint.AtSink(values[64]));
    }

    [Fact]
    public void UnsupportedHostingContextDoesNotCreateAnAmbientScope()
    {
        Assert.Null(HttpRequestTracking.Begin(new object()));
        Assert.Null(SecurityRequestContext.Current);
    }

    private sealed class HostingContext(Dictionary<string, string[]> query)
    {
        public RequestContext HttpContext { get; } = new(query);
    }

    private sealed class RequestContext(Dictionary<string, string[]> query)
    {
        public RequestData Request { get; } = new(query);

        public ResponseData Response { get; } = new();
    }

    private sealed class ResponseData
    {
        public int StatusCode { get; } = 200;

        public bool HasStarted { get; }
    }

    private sealed class RequestData(Dictionary<string, string[]> query)
    {
        public Dictionary<string, string[]> Query { get; } = query;

        public string Method { get; } = "GET";
    }
}
