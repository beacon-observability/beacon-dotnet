// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using Newtonsoft.Json.Linq;
using OpenTelemetry.AutoInstrumentation.Security;

namespace OpenTelemetry.AutoInstrumentation.Tests.Security;

public class FindingFingerprintTests
{
    [Fact]
    public void MatchesEveryPinnedConformanceVector()
    {
        var document = JObject.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Security", "fingerprint-v1.json")));
        foreach (var vector in document["vectors"]!)
        {
            var input = vector["input"]!;
            var sink = input["sink"]!;
            var actual = FindingFingerprint.Compute(
                (string)input["application_id"]!,
                (string)input["language"]!,
                (string)input["rule"]!,
                (string)sink["role"]!,
                (string)sink["function"]!,
                (string)sink["location"]!,
                (string)sink["operation"]!,
                (string)sink["path_role"]!,
                (string)sink["input_part"]!,
                input["source_signatures"]!.Values<string>().Select(value => value!));
            Assert.Equal((string)vector["expected"]!, actual);
        }
    }

    [Fact]
    public void UnpairedSurrogatesUseReplacementCharacter()
    {
        Assert.Equal(
            FindingFingerprint.ApplicationId(string.Empty, "\uFFFD"),
            FindingFingerprint.ApplicationId(string.Empty, "\uD800"));
    }
}
