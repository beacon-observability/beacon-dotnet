// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

namespace OpenTelemetry.AutoInstrumentation.Security;

internal sealed class RequestDetails(string? method, string? route, int? statusCode, string? errorType)
{
    public string? Method { get; } = method;

    public string? Route { get; } = route;

    public int? StatusCode { get; } = statusCode;

    public string? ErrorType { get; } = errorType;
}
