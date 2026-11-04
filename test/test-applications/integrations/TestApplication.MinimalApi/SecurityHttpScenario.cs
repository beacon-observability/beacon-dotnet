// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

namespace TestApplication.MinimalApi;

internal static class SecurityHttpScenario
{
    private static readonly ConcurrentBag<object> Scopes = new();

    public static int DistinctScopes => Scopes.Distinct(ReferenceEqualityComparer.Instance).Count();

    public static void DrainLocalOutput()
    {
        // Only the diagnostic fixture requests an explicit drain. Normal process exit
        // is best effort and does not wait for a blocked filesystem.
        var assembly = AppDomain.CurrentDomain.GetAssemblies().Single(candidate => candidate.GetName().Name == "OpenTelemetry.AutoInstrumentation");
        var instrumentation = assembly.GetType("OpenTelemetry.AutoInstrumentation.Instrumentation", true)!;
        var output = instrumentation.GetProperty("LocalSecurityOutput", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null);
        if (output is IDisposable disposable)
        {
            disposable.Dispose();
            var completion = (Task)output.GetType().GetProperty("Completion", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(output)!;
            if (!completion.Wait(TimeSpan.FromSeconds(10)))
            {
                throw new TimeoutException("Local diagnostic fixture did not drain.");
            }

            completion.GetAwaiter().GetResult();
        }
    }

    public static async Task<string> SendAsync(string input, string configuredDestination, string mode)
    {
        var destination = mode switch
        {
            "constant" => configuredDestination,
            "query" => string.Concat(configuredDestination, "&value=", input),
            "fragment" => string.Concat(configuredDestination, "#", input),
            "path" => string.Concat(configuredDestination.Split('?')[0], "/", input),
            _ => input,
        };
        if (!Uri.TryCreate(destination, UriKind.Absolute, out var uri) || !uri.IsLoopback)
        {
            throw new InvalidOperationException("This test only permits loopback destinations.");
        }

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        await client.GetStringAsync(uri).ConfigureAwait(false);
        await client.GetStringAsync(uri).ConfigureAwait(false);
        return "ok";
    }

    public static string Observe(string input)
    {
        var assembly = AppDomain.CurrentDomain.GetAssemblies().Single(candidate => candidate.GetName().Name == "OpenTelemetry.AutoInstrumentation");
        var contextType = assembly.GetType("OpenTelemetry.AutoInstrumentation.Security.SecurityRequestContext", true)!;
        var scope = contextType.GetProperty("Current")!.GetValue(null);
        if (Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_PROCESS") is { } processMode)
        {
            RunProcess(input, processMode);
        }

        if (Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_SQL") is { } sqlMode)
        {
            ExecuteSql(input, sqlMode == "parameterized");
        }

        if (Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_FINDING") == "true")
        {
            ReadAttempt(Join(input));
            ReadAttempt(Join(input));
        }

        if (scope is null)
        {
            return "HTTP_SOURCE_RANGES=0";
        }

        var taint = contextType.GetProperty("Taint")!.GetValue(scope)!;
        Scopes.Add(scope);
        var ranges = (Array)taint.GetType().GetMethod("AtSink")!.Invoke(taint, [Join(input)])!;
        return $"HTTP_SOURCE_RANGES={ranges.Length}";
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void RunProcess(string input, string mode)
    {
        // This integration fixture is loopback-only and accepts these two fixed values
        // before constructing any shell script. It never executes arbitrary test input.
        if (input is not "first-request" and not "second-request")
        {
            throw new InvalidOperationException("Unexpected process test input.");
        }

        var windows = OperatingSystem.IsWindows();
        var executable = windows
            ? Path.Combine(Environment.SystemDirectory, mode == "shell" ? "CMD.EXE" : "whoami.exe")
            : mode == "shell" ? "/bin/sh" : "/bin/echo";
        var info = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (mode == "executable")
        {
            var missingDirectory = Path.Combine(Path.GetTempPath(), "beacon-missing-" + Guid.NewGuid().ToString("N")) + Path.DirectorySeparatorChar;
            info.FileName = string.Concat(missingDirectory, input);
        }

        if (mode == "shell")
        {
            info.ArgumentList.Add(windows ? "/c" : "-c");
            info.ArgumentList.Add(windows ? string.Concat("echo ", input) : string.Concat("printf '%s' '", input, "'"));
        }
        else
        {
            info.ArgumentList.Add(mode is "constant" or "executable" ? "fixed-value" : input);
        }

        for (var index = 0; index < 2; index++)
        {
            using var process = new Process { StartInfo = info };
            try
            {
                process.Start();
            }
            catch (System.ComponentModel.Win32Exception) when (mode == "executable")
            {
                continue;
            }

            // whoami intentionally receives a fixed invalid argument on Windows.
            // These observations describe invocation attempts, including failed exits.
            if (!process.WaitForExit(5000) || ((!windows || mode == "shell") && process.ExitCode != 0))
            {
                throw new InvalidOperationException("Process test did not complete successfully.");
            }

            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ExecuteSql(string input, bool parameterized)
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var command = connection.CreateCommand();
        if (parameterized)
        {
            command.CommandText = "SELECT $value";
            command.Parameters.AddWithValue("$value", input);
        }
        else
        {
#pragma warning disable CA2100 // Deliberately exercise an untrusted template in an isolated in-memory test database.
            command.CommandText = string.Concat("SELECT '", input, "'");
#pragma warning restore CA2100
        }

        command.Prepare();
        if (Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_SQL_ASYNC") == "true")
        {
            command.ExecuteScalarAsync().GetAwaiter().GetResult();
            command.ExecuteScalarAsync().GetAwaiter().GetResult();
        }
        else
        {
            command.ExecuteScalar();
            command.ExecuteScalar();
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ReadAttempt(string path)
    {
        try
        {
            File.ReadAllText(path);
        }
        catch (IOException)
        {
            // A failed call still observes an invocation attempt, never an exploit outcome.
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string Join(string input)
    {
        return string.Concat("prefix", input);
    }
}
