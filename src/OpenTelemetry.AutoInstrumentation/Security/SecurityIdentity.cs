// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

namespace OpenTelemetry.AutoInstrumentation.Security;

internal static class SecurityIdentity
{
    public static string InstanceId { get; } = Guid.NewGuid().ToString("D");
}
