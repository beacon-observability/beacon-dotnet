// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Data;
using OpenTelemetry.AutoInstrumentation.CallTarget;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Instrumentations.AdoNet.Integrations;

/// <summary>
/// ADO.NET DbCommand.ExecuteDbDataReader instrumentation.
/// </summary>
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataCommonAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SystemDataCommonMinVersion,
    maximumVersion: AdoNetConstants.SystemDataCommonMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SystemDataMinVersion,
    maximumVersion: AdoNetConstants.SystemDataMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.NetStandardAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.NetStandardMinVersion,
    maximumVersion: AdoNetConstants.NetStandardMaxVersion,
    integrationName: AdoNetConstants.IntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SqliteMicrosoft.AssemblyName,
    typeName: AdoNetConstants.SqliteMicrosoft.CommandTypeName,
    methodName: AdoNetConstants.ExecuteReaderMethodName,
    returnTypeName: AdoNetConstants.SqliteMicrosoft.DataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SqliteMicrosoft.MinVersion,
    maximumVersion: AdoNetConstants.SqliteMicrosoft.MaxVersion,
    integrationName: AdoNetConstants.SqliteMicrosoft.SqliteIntegrationName,
    type: InstrumentationType.Trace,
    kind: IntegrationKind.Direct)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataCommonAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SystemDataCommonMinVersion,
    maximumVersion: AdoNetConstants.SystemDataCommonMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SystemDataAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SystemDataMinVersion,
    maximumVersion: AdoNetConstants.SystemDataMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.NetStandardAssemblyName,
    typeName: AdoNetConstants.DbCommandTypeName,
    methodName: AdoNetConstants.ExecuteDbDataReaderMethodName,
    returnTypeName: AdoNetConstants.DbDataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.NetStandardMinVersion,
    maximumVersion: AdoNetConstants.NetStandardMaxVersion,
    integrationName: "Security",
    type: InstrumentationType.Security,
    kind: IntegrationKind.Derived)]
[InstrumentMethod(
    assemblyName: AdoNetConstants.SqliteMicrosoft.AssemblyName,
    typeName: AdoNetConstants.SqliteMicrosoft.CommandTypeName,
    methodName: AdoNetConstants.ExecuteReaderMethodName,
    returnTypeName: AdoNetConstants.SqliteMicrosoft.DataReaderTypeName,
    parameterTypeNames: [AdoNetConstants.CommandBehaviorTypeName],
    minimumVersion: AdoNetConstants.SqliteMicrosoft.MinVersion,
    maximumVersion: AdoNetConstants.SqliteMicrosoft.MaxVersion,
    integrationName: AdoNetConstants.SqliteMicrosoft.SqliteIntegrationName,
    type: InstrumentationType.Security,
    kind: IntegrationKind.Direct)]
public static class CommandExecuteDbDataReaderIntegration
{
    internal static CallTargetState OnMethodBegin<TTarget>(TTarget instance, CommandBehavior behavior)
    {
        var activity = AdoNetInstrumentation.StartActivity(instance, AdoNetConstants.ExecuteDbDataReaderMethodName);
        return new CallTargetState(activity, SecuritySqlScope.Begin(instance!, AdoNetConstants.ExecuteDbDataReaderMethodName));
    }

    internal static CallTargetReturn<TReturn> OnMethodEnd<TTarget, TReturn>(TTarget instance, TReturn returnValue, Exception? exception, in CallTargetState state)
    {
        AdoNetInstrumentation.StopActivity(state.Activity, exception);
        (state.State as SecuritySqlScope)?.Dispose();
        return new CallTargetReturn<TReturn>(returnValue);
    }
}
