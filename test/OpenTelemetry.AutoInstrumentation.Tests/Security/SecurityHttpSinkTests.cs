// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Net.Http;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityHttpSinkTests
{
    [Theory]
    [InlineData("http://127.0.0.1/destination?q=", "query")]
    [InlineData("http://127.0.0.1/destination/", "path")]
    [InlineData("http://127.0.0.1/destination#", null)]
    public void QueryOnlyInputIsNotAnAddressAndFragmentOnlyInputIsNotSent(string prefix, string? inputPart)
    {
        using var scope = SecurityRequestContext.Begin("app-http");
        var input = new string('x', 3);
        scope.Taint.Source(input, "http.request.parameter", "value", "request.query");
        var destination = string.Concat(prefix, input);
        scope.Taint.Concat(destination, [prefix, input]);
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);
        SecurityHttpSink.Observe(request);
        var observations = scope.Findings.Close();
        if (inputPart is not null)
        {
            var observation = Assert.Single(observations);
            Assert.Equal("http_request_input", observation.Rule);
            Assert.Equal("path_or_query", observation.Sink.Role);
            Assert.Equal(inputPart, observation.Sink.InputPart);
        }
        else
        {
            Assert.Empty(observations);
        }
    }

    [Fact]
    public void OriginalUriIdentityProducesAnUnknownDestinationPolicyObservation()
    {
        using var scope = SecurityRequestContext.Begin("app-http");
        var input = new string("http://127.0.0.1/private?secret=value".ToCharArray());
        scope.Taint.Source(input, "http.request.parameter", "target", "request.query");
        using var request = new HttpRequestMessage(HttpMethod.Get, input);
        Assert.Same(input, request.RequestUri!.OriginalString);
        SecurityHttpSink.Observe(request);
        SecurityHttpSink.Observe(request);
        var observation = Assert.Single(scope.Findings.Close());
        Assert.Equal("ssrf", observation.Rule);
        Assert.Equal("destination_address", observation.Sink.Role);
        Assert.Equal(RequestFindings.EvidenceStatus.Unknown, observation.Evidence.Status);
        Assert.DoesNotContain("secret", FindingEvent.Encode(observation, true)!, StringComparison.Ordinal);
    }

    [Fact]
    public void EqualButUntrackedDestinationDoesNotEstablishSourceFlow()
    {
        using var scope = SecurityRequestContext.Begin("app-http");
        var input = new string("http://127.0.0.1/private".ToCharArray());
        scope.Taint.Source(input, "http.request.parameter", "target", "request.query");
        using var request = new HttpRequestMessage(HttpMethod.Get, new string(input.ToCharArray()));
        SecurityHttpSink.Observe(request);
        Assert.Empty(scope.Findings.Close());
    }
}
