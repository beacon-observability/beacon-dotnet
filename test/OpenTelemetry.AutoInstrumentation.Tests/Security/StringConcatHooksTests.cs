// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class StringConcatHooksTests
{
    private delegate CallTargetReturn<string> EndInvoker(object instance, string value, Exception exception, in CallTargetState state);

    [Fact]
    public void CallTargetMapperBindsStaticConcatAndPreservesReturnIdentity()
    {
        using var context = SecurityRequestContext.Begin("app-test");
        var input = new string('x', 3);
        var prefix = "prefix";
        context.Taint.Source(input, "http.request.parameter", "id", "request.query");
        var begin = typeof(CallTargetInvoker).GetMethods().Single(method => method.Name == "BeginMethod" && method.GetGenericArguments().Length == 4)
            .MakeGenericMethod(typeof(StringConcat2Integration), typeof(object), typeof(string), typeof(string));
        var state = (CallTargetState)begin.Invoke(null, [null, prefix, input])!;
        var actual = string.Concat(prefix, input);
        var end = typeof(CallTargetInvoker).GetMethods().Single(method => method.Name == "EndMethod" && method.GetGenericArguments().Length == 3)
            .MakeGenericMethod(typeof(StringConcat2Integration), typeof(object), typeof(string));
#if NETFRAMEWORK
        var invokeEnd = (EndInvoker)end.CreateDelegate(typeof(EndInvoker));
#else
        var invokeEnd = end.CreateDelegate<EndInvoker>();
#endif
        var returned = invokeEnd(null!, actual, null!, in state);
        Assert.Same(actual, returned.GetReturnValue());
        Assert.Equal(6, Assert.Single(context.Taint.AtSink(actual)).Start);
    }

    [Fact]
    public void NoRequestCreatesNoTrackingState()
    {
        Assert.Null(SecurityRequestContext.Current);
        var state = StringConcat2Integration.OnMethodBegin<object>(null!, "one", "two");
        Assert.Null(state.State);
    }

    [Fact]
    public async Task AmbientContextFlowsToChildrenAndClosesWithoutCrossRequestLeak()
    {
        using var parent = SecurityRequestContext.Begin("app-parent");
        await Task.Run(() =>
        {
            Assert.Same(parent, SecurityRequestContext.Current);
            using var child = SecurityRequestContext.Begin("app-child");
            Assert.Same(child, SecurityRequestContext.Current);
        }).ConfigureAwait(true);
        Assert.Same(parent, SecurityRequestContext.Current);
        var value = new string('x', 2);
        parent.Taint.Source(value, "http.request.parameter", "id", "request.query");
        parent.Dispose();
        Assert.Null(SecurityRequestContext.Current);
        Assert.Empty(parent.Taint.AtSink(value));
    }
}
