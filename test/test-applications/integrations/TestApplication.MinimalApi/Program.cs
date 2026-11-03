// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

using System.Net.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using TestApplication.MinimalApi;

using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder
                .AddFilter("Microsoft", LogLevel.Warning);
        });
var logger = loggerFactory.CreateLogger<Program>();
logger.LogBeforeHostBuilt();
var builder = WebApplication.CreateBuilder(args);
var securityBenchmark = Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_BENCHMARK");
if (securityBenchmark is not null)
{
    builder.Logging.ClearProviders();
}

using var app = builder.Build();
string? configuredDestination = null;
var securityScenario = Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_HTTP") == "true" || securityBenchmark is not null;
var ssrfScenario = Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_SSRF") is { };
if (securityScenario)
{
    if (securityBenchmark is not null)
    {
        app.MapGet("/security-load", (HttpContext context) => SecurityLoadScenario.Handle(context.Request.Query["id"].ToString(), context.Request.Query["probe"] == "true"));
    }

    app.MapGet("/security", async (HttpContext context) =>
    {
        await Task.Yield();
        return SecurityHttpScenario.Observe(context.Request.Query["id"].ToString());
    });
    app.MapGet("/destination", () => "ok");
    app.MapGet("/destination/{**rest}", () => "ok");
    app.MapGet("/security-http", async (HttpContext context) =>
    {
        await Task.Yield();
        return await SecurityHttpScenario.SendAsync(context.Request.Query["target"].ToString(), configuredDestination!, Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_SSRF")!).ConfigureAwait(false);
    });
}

app.MapGet("/test", (ILogger<Program> logger) =>
{
    logger.LogRequestReceived();
    return "Hello World!";
});

app.Start();

var server = (IServer?)app.Services.GetService(typeof(IServer));
var addressFeature = server?.Features.Get<IServerAddressesFeature>();
var address = addressFeature?.Addresses.First();
configuredDestination = $"{address}/destination?private-marker=value";

using var httpClient = new HttpClient();
if (securityBenchmark is not null)
{
    SecurityLoadScenario.Run(httpClient, address!, securityBenchmark);
    app.StopAsync().GetAwaiter().GetResult();
}
else if (ssrfScenario)
{
    var input = Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_SSRF") == "path" ? "private-value" : configuredDestination;
    var request = new Uri($"{address}/security-http?target={Uri.EscapeDataString(input)}");
    Task.WhenAll(httpClient.GetStringAsync(request), httpClient.GetStringAsync(request)).GetAwaiter().GetResult();
}
else if (securityScenario)
{
    var responses = Task.WhenAll(
        httpClient.GetStringAsync(new Uri($"{address}/security?id=first-request")),
        httpClient.GetStringAsync(new Uri($"{address}/security?id=second-request"))).GetAwaiter().GetResult();
    foreach (var response in responses)
    {
        Console.WriteLine(response);
    }

    Console.WriteLine($"HTTP_DISTINCT_SCOPES={SecurityHttpScenario.DistinctScopes}");
}
else
{
    httpClient.GetAsync(new Uri($"{address}/test")).Wait();
}

if (Environment.GetEnvironmentVariable("BEACON_TEST_SECURITY_LOCAL_DRAIN") == "true")
{
    app.StopAsync().GetAwaiter().GetResult();
    SecurityHttpScenario.DrainLocalOutput();
}

internal static partial class LoggerExtensions
{
    [LoggerMessage(Level = LogLevel.Information, Message = "Logged before host is built.")]
    public static partial void LogBeforeHostBuilt(this ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Request received.")]
    public static partial void LogRequestReceived(this ILogger logger);
}
