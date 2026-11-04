// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using OpenTelemetry.AutoInstrumentation.Tests.Util;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

[Collection("Non-Parallel Collection")]
public class SecurityDefinitionsTests
{
    [Theory]
    [InlineData(null, 0)]
    [InlineData("false", 0)]
    [InlineData("invalid", 0)]
    [InlineData("true", 10)]
    public void RegistersSecurityDefinitionsOnlyWhenEnabled(string? configured, int expected)
    {
        using var environment = new EnvironmentScope(new Dictionary<string, string?> { ["BEACON_SECURITY_ENABLED"] = configured });
        var definitions = InstrumentationDefinitions.GetAllDefinitions().Definitions;
        try
        {
            var security = definitions.Where(definition => definition.IntegrationType.StartsWith("OpenTelemetry.AutoInstrumentation.Security.", StringComparison.Ordinal)).ToArray();
            Assert.Equal(expected, security.Length);
            Assert.All(security, definition => Assert.True(definition.TargetMethod is "Concat" or "ProcessRequestAsync" or "ReadAllText" or "SendAsync" or "Start"));
        }
        finally
        {
            foreach (var definition in definitions)
            {
                definition.Dispose();
            }
        }
    }
}
