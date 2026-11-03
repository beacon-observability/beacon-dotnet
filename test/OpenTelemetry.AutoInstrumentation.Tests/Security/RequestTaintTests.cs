// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class RequestTaintTests
{
    [Fact]
    public void EqualContentDoesNotEstablishObjectIdentityFlow()
    {
        var request = new RequestTaint();
        var source = new string('x', 6);
        var unrelated = new string('x', 6);
        request.Source(source, "http.request.parameter", "id", "request.query");
        Assert.Single(request.AtSink(source));
        Assert.Empty(request.AtSink(unrelated));
        Assert.Empty(new RequestTaint().AtSink(source));
    }

    [Fact]
    public void ConcatPreservesUtf16OffsetsAndSourceMetadataWithoutRawValues()
    {
        var request = new RequestTaint();
        var source = new string(['a', '\ud83d', '\ude00']);
        request.Source(source, "http.request.parameter", "id", "request.query");
        var sql = string.Concat("SELECT '", source, "'");
        request.Concat(sql, ["SELECT '", source, "'"]);
        var range = Assert.Single(request.AtSink(sql));
        Assert.Equal(8, range.Start);
        Assert.Equal(11, range.End);
        Assert.Equal(3, range.Source.ValueLength);
        Assert.Equal("id", range.Source.Name);
        var decorated = string.Concat("prefix", sql);
        request.Concat(decorated, ["prefix", sql]);
        Assert.Equal(14, Assert.Single(request.AtSink(decorated)).Start);
        Assert.True(request.Complete);
    }

    [Fact]
    public void UnsupportedPropagationCannotCreateTaint()
    {
        var request = new RequestTaint();
        var source = new string('a', 2);
        request.Source(source, "http.request.parameter", "id", "request.query");
        var unrelated = new string('b', 2);
        request.Concat(unrelated, [source]);
        Assert.Empty(request.AtSink(unrelated));
        Assert.False(request.Complete);
    }

    [Fact]
    public void BudgetsDeclareIncompleteCollectionWithoutLosingExistingEvidence()
    {
        var request = new RequestTaint(maxOperations: 1);
        var source = new string('a', 2);
        request.Source(source, "http.request.parameter", "id", "request.query");
        var result = string.Concat(source, "suffix");
        request.Concat(result, [source, "suffix"]);
        Assert.Empty(request.AtSink(result));
        Assert.Single(request.AtSink(source));
        Assert.False(request.Complete);
    }

    [Fact]
    public void ClosedRequestCannotBeObservedOrExtendedByChildContexts()
    {
        var request = new RequestTaint();
        var source = new string('a', 2);
        request.Source(source, "http.request.parameter", "id", "request.query");
        request.Close();
        request.Source(source, "http.request.parameter", "other", "request.query");
        Assert.Empty(request.AtSink(source));
    }

    [Fact]
    public void RepeatedObjectCanCarryMultipleSourcesWithinTheRequest()
    {
        var request = new RequestTaint();
        var source = new string('a', 2);
        request.Source(source, "http.request.parameter", "first", "request.query");
        request.Source(source, "http.request.parameter", "second", "request.query");
        Assert.Equal(2, request.AtSink(source).Length);
        Assert.NotEqual(request.AtSink(source)[0].Source.Id, request.AtSink(source)[1].Source.Id);
    }
}
