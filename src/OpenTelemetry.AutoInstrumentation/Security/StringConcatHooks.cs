// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Runtime.CompilerServices;
using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.CallTarget.Handlers;

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class StringConcatHooks
{
    private static readonly Lazy<bool> Prepared = new(PrepareDelegates);

    [ThreadStatic]
    private static bool _busy;

    public static bool Prepare()
    {
        return Prepared.Value;
    }

    public static CallTargetState Begin(string?[] inputs)
    {
        var context = SecurityRequestContext.Current;
        return context is null || _busy ? CallTargetState.GetDefault() : new CallTargetState(null, new ConcatState(context, inputs));
    }

    public static void End(string result, Exception? exception, in CallTargetState state)
    {
        if (exception is not null || _busy || state.State is not ConcatState concat)
        {
            return;
        }

        try
        {
            _busy = true;
            concat.Context.Taint.Concat(result, concat.Inputs);
        }
        catch (Exception)
        {
            // Instrumentation must not change application results or exception behavior.
        }
        finally
        {
            _busy = false;
        }
    }

    private static bool PrepareDelegates()
    {
        try
        {
            _ = SecurityRequestContext.Current;
            foreach (var target in new[] { typeof(object), typeof(string) })
            {
                var integrations = new[] { typeof(StringConcat2Integration), typeof(StringConcat3Integration), typeof(StringConcat4Integration) };
                var handlers = new[] { typeof(BeginMethodHandler<,,,>), typeof(BeginMethodHandler<,,,,>), typeof(BeginMethodHandler<,,,,,>) };
                for (var index = 0; index < integrations.Length; index++)
                {
                    var arguments = new[] { integrations[index], target }.Concat(Enumerable.Repeat(typeof(string), index + 2)).ToArray();
                    RuntimeHelpers.RunClassConstructor(handlers[index].MakeGenericType(arguments).TypeHandle);
                    RuntimeHelpers.RunClassConstructor(typeof(EndMethodHandler<,,>).MakeGenericType(integrations[index], target, typeof(string)).TypeHandle);
                    RuntimeHelpers.RunClassConstructor(typeof(IntegrationOptions<,>).MakeGenericType(integrations[index], target).TypeHandle);
                    // Execute the entry path before CoreLib interception. A cctor alone
                    // does not resolve Activity.Current's lazy runtime dependencies.
                    var invokeArguments = new object?[index + 3];
                    for (var argument = 1; argument < invokeArguments.Length; argument++)
                    {
                        invokeArguments[argument] = string.Empty;
                    }

                    handlers[index].MakeGenericType(arguments).GetMethod("Invoke", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.Invoke(null, invokeArguments);
                }
            }

            foreach (var target in new[] { typeof(object), typeof(File) })
            {
                var handler = typeof(BeginMethodHandler<,,>).MakeGenericType(typeof(FileReadAllTextIntegration), target, typeof(string));
                RuntimeHelpers.RunClassConstructor(handler.TypeHandle);
                RuntimeHelpers.RunClassConstructor(typeof(EndMethodHandler<,,>).MakeGenericType(typeof(FileReadAllTextIntegration), target, typeof(string)).TypeHandle);
                RuntimeHelpers.RunClassConstructor(typeof(IntegrationOptions<,>).MakeGenericType(typeof(FileReadAllTextIntegration), target).TypeHandle);
                handler.GetMethod("Invoke", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!.Invoke(null, [null, string.Empty]);
            }

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private sealed class ConcatState(SecurityRequestContext context, string?[] inputs)
    {
        public SecurityRequestContext Context { get; } = context;

        public string?[] Inputs { get; } = inputs;
    }
}
