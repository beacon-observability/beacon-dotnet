// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Data;
using NSubstitute;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecuritySqlScopeTests
{
    [Fact]
    public void CommandMetadataFailureDoesNotChangeApplicationBehaviorAndMarksIncomplete()
    {
        using var request = SecurityRequestContext.Begin("app-sql");
        using var command = Substitute.For<IDbCommand>();
        command.CommandType.Returns(CommandType.Text);
        command.CommandText.Returns(_ => throw new InvalidOperationException("Provider failure."));
        Assert.Null(SecuritySqlScope.Begin(command, "ExecuteScalar"));
        Assert.False(request.Taint.Complete);
    }

    [Fact]
    public void ReentrantProviderMetadataIsNotInspectedRecursively()
    {
        using var request = SecurityRequestContext.Begin("app-sql");
        using var command = Substitute.For<IDbCommand>();
        command.CommandType.Returns(CommandType.Text);
        command.CommandText.Returns(_ =>
        {
            Assert.Null(SecuritySqlScope.Begin(command, "ExecuteScalar"));
            return "SELECT 1";
        });
        Assert.Null(SecuritySqlScope.Begin(command, "ExecuteScalar"));
        Assert.True(request.Taint.Complete);
    }

    [Fact]
    public void SuppressesNestedCallbacksForTheSameCommandAndReleasesOnCompletion()
    {
        using var request = SecurityRequestContext.Begin("app-sql");
        var input = new string('x', 3);
        request.Taint.Source(input, "http.request.parameter", "id", "request.query");
        var text = string.Concat("SELECT '", input, "'");
        request.Taint.Concat(text, ["SELECT '", input, "'"]);
        using var command = Substitute.For<IDbCommand>();
        command.CommandType.Returns(CommandType.Text);
        command.CommandText.Returns(text);
        using var first = SecuritySqlScope.Begin(command, "ExecuteScalar");
        Assert.NotNull(first);
        Assert.Null(SecuritySqlScope.Begin(command, "ExecuteDbDataReader"));
        first.Dispose();
        using var second = SecuritySqlScope.Begin(command, "ExecuteScalar");
        Assert.NotNull(second);
        var finding = Assert.Single(request.Findings.Close());
        Assert.Equal("sql_injection", finding.Rule);
        Assert.Equal("sql_template", finding.Sink.Role);
    }

    [Fact]
    public void BoundValuesDoNotTaintAnUnchangedSqlTemplate()
    {
        using var request = SecurityRequestContext.Begin("app-sql");
        var input = new string('x', 3);
        request.Taint.Source(input, "http.request.parameter", "id", "request.query");
        using var command = Substitute.For<IDbCommand>();
        command.CommandType.Returns(CommandType.Text);
        command.CommandText.Returns("SELECT $value");
        Assert.Null(SecuritySqlScope.Begin(command, "ExecuteScalar"));
        Assert.Empty(request.Findings.Close());
    }
}
