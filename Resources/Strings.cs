using System.Globalization;
using System.Resources;

namespace DnsChecker.Resources;

/// <summary>
/// Provides localized strings for user-facing prompts.
/// </summary>
internal static class Strings
{
    private static readonly ResourceManager ResourceManager = new("DnsChecker.Resources.Strings", typeof(Strings).Assembly);

    internal static string RetryFailedPrompt =>
        ResourceManager.GetString("RetryFailedPrompt", CultureInfo.CurrentCulture) ?? "Retry failed domains and append results? (Y/N)";

    internal static string RetryAppendedMessageFormat =>
        ResourceManager.GetString("RetryAppendedMessageFormat", CultureInfo.CurrentCulture) ?? "Retry results appended to: {0}";

    internal static string ResumePrompt =>
        ResourceManager.GetString("ResumePrompt", CultureInfo.CurrentCulture) ?? "Resume previous run? (Y/N)";

    internal static string ResumeAllProcessedPrompt =>
        ResourceManager.GetString("ResumeAllProcessedPrompt", CultureInfo.CurrentCulture) ?? "All domains were already processed. Re-run all domains? (Y/N)";

    internal static string ResumeCacheClearedMessage =>
        ResourceManager.GetString("ResumeCacheClearedMessage", CultureInfo.CurrentCulture) ?? "Resume cache cleared. Re-running all domains.";

    internal static string NoDomainsToProcessMessage =>
        ResourceManager.GetString("NoDomainsToProcessMessage", CultureInfo.CurrentCulture) ?? "No domains to process.";
}
