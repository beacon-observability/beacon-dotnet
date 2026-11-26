// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class SecurityFindingExportTests
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("false", false)]
    [InlineData("invalid", false)]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    public void NoEvidenceRequiresExplicitOptIn(string? setting, bool expected)
    {
        Assert.Equal(expected, SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.NoEvidence, setting));
        Assert.True(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.Unknown, setting));
        Assert.True(SecurityFindingExport.ShouldExport(RequestFindings.EvidenceStatus.Suspected, setting));
    }
}
