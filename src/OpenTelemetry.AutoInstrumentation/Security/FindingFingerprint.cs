// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Security.Cryptography;
using System.Text;

namespace OpenTelemetry.AutoInstrumentation.Security;

/// <summary>
/// Implements the language-neutral Beacon finding identity contract, version 1.
/// </summary>
internal static class FindingFingerprint
{
    private static readonly Encoding Utf8 = new UTF8Encoding(false, false);

    public static string ApplicationId(string serviceNamespace, string serviceName)
    {
#if NETFRAMEWORK
        using var sha = SHA256.Create();
        return "app-" + Hex(sha.ComputeHash(Utf8.GetBytes(serviceNamespace + "|" + serviceName)));
#else
        return "app-" + Hex(SHA256.HashData(Utf8.GetBytes(serviceNamespace + "|" + serviceName)));
#endif
    }

    public static string Compute(
        string applicationId,
        string language,
        string rule,
        string role,
        string function,
        string location,
        string operation,
        string pathRole,
        string inputPart,
        IEnumerable<string> sourceSignatures)
    {
        using var sha = SHA256.Create();
        var segments = new[] { "1", applicationId, language, rule, role, function, location, operation, pathRole, inputPart }
            .Concat(sourceSignatures.Select(signature => Utf8.GetString(Utf8.GetBytes(signature)))
                .Distinct(StringComparer.Ordinal).OrderBy(signature => signature, StringComparer.Ordinal));

        foreach (var segment in segments)
        {
            // UTF-8's replacement fallback normalizes unpaired UTF-16 surrogates to U+FFFD.
            // Prefix byte lengths, not character counts, in network byte order on every platform.
            var bytes = Utf8.GetBytes(segment);
            var length = bytes.Length;
            var prefix = new[] { (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length };
            sha.TransformBlock(prefix, 0, prefix.Length, null, 0);
            sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        }

        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return "finding-" + Hex(sha.Hash!);
    }

    private static string Hex(byte[] bytes)
    {
        // The contract requires lowercase hex, including on .NET Framework.
        const string alphabet = "0123456789abcdef";
        var characters = new char[bytes.Length * 2];
        for (var index = 0; index < bytes.Length; index++)
        {
            characters[index * 2] = alphabet[bytes[index] >> 4];
            characters[(index * 2) + 1] = alphabet[bytes[index] & 15];
        }

        return new string(characters);
    }
}
