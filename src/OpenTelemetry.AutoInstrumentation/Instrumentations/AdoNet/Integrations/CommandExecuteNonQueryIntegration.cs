// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Instrumentations.AdoNet.Integrations;

/// <summary>
/// ADO.NET DbCommand.ExecuteNonQuery instrumentation.
/// </summary>
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataCommonAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.SystemDataCommonMinVersion,
    maximumVersion: AdoNetConstants.SystemDataCommonMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.SystemDataMinVersion,
    maximumVersion: AdoNetConstants.SystemDataMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.NetStandardAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.NetStandardMinVersion,
    maximumVersion: AdoNetConstants.NetStandardMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.Devart.Oracle.AssemblyName,
    typeName: AdoNetConstants.Devart.Oracle.CommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.Devart.Oracle.MinVersion,
    maximumVersion: AdoNetConstants.Devart.Oracle.MaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Direct)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataCommonAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.SystemDataCommonMinVersion,
    maximumVersion: AdoNetConstants.SystemDataCommonMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.SystemDataMinVersion,
    maximumVersion: AdoNetConstants.SystemDataMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.NetStandardAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.NetStandardMinVersion,
    maximumVersion: AdoNetConstants.NetStandardMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.Devart.Oracle.AssemblyName,
    typeName: AdoNetConstants.Devart.Oracle.CommandTypeName,
    methodName: AdoNetConstants.ExecuteNonQueryMethodName,
    returnTypeName: ClrNames.Int32,
    parameterTypeNames: [],
    minimumVersion: AdoNetConstants.Devart.Oracle.MinVersion,
    maximumVersion: AdoNetConstants.Devart.Oracle.MaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Direct)]
public static class CommandExecuteNonQueryIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance)
    {
        var activity = AdoNetInstrumentation.StartActivity(instance, AdoNetConstants.ExecuteNonQueryMethodName);
        return new CallTargetState(activity, SecuritySqlScope.Begin(instance!, AdoNetConstants.ExecuteNonQueryMethodName));
    }

    internal static CallTargetReturn<TReturn> OnMethodEnd<TTarget, TReturn>(TTarget instance, TReturn returnValue, Exception? exception, in CallTargetState state)
    {
        AdoNetInstrumentation.StopActivity(state.Activity, exception);
        (state.State as SecuritySqlScope)?.Dispose();
        return new CallTargetReturn<TReturn>(returnValue);
    }
}
