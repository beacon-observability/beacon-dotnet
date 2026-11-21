using Fallout.Common;
using Fallout.Common.IO;

partial class Build
{
    AbsolutePath InstallationScriptsDirectory => OutputDirectory / "installation-scripts";

    Target BuildInstallationScripts => _ => _
        .After(Clean)
        .After(CreateRequiredDirectories)
        .Executes(() =>
        {
            var versionFile = RootDirectory / "beacon" / "version.properties";
            var versionLines = File.ReadAllLines(versionFile)
                .Where(line => line.StartsWith("beacon.version=", StringComparison.Ordinal))
                .ToArray();
            if (versionLines.Length != 1)
            {
                throw new InvalidOperationException($"Expected exactly one beacon.version in {versionFile}.");
            }

            var beaconVersion = versionLines[0]["beacon.version=".Length..];
            var scriptTemplates = RootDirectory / "script-templates";
            var templateFiles = scriptTemplates.GetFiles();
            foreach (var templateFile in templateFiles)
            {
                var scriptFile = InstallationScriptsDirectory / templateFile.Name.Replace(".template", "");
                templateFile.Copy(scriptFile, ExistsPolicy.FileOverwrite);
                scriptFile.UpdateText(x =>
                    x.Replace("{{VERSION}}", beaconVersion));
            }
        });
}
