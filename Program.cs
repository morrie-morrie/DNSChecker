using DnsChecker.Entities;
using DnsChecker.Helpers;
using DnsChecker.Resources;
using DnsClient;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace DnsChecker;

public static class Program
{
    private static int ProgressLineLength;

    private static async Task Main(string[] args)
    {
        try
        {
            // Set up configuration
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .Build();

            Console.WriteLine("---------------------");
            Console.WriteLine("Application started");

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            Console.WriteLine();
            Console.WriteLine($"DNS Checker - Version: {version}");
            Console.WriteLine();

            // Get DNS server from configuration
            string dnsServerAddressString = configuration["DnsServerAddress"] ?? "8.8.8.8";
            
            // Prepare for DNS server selection
            Console.Write($"Using DNS server address from configuration: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(dnsServerAddressString);
            Console.ResetColor();

            // Prompt for DNS server change
            Console.WriteLine($"Do you want to use a different DNS server? (Y/N)");
            string? response = Console.ReadLine()?.Trim().ToUpperInvariant();

            if (!IPAddress.TryParse(dnsServerAddressString, out IPAddress? dnsServerAddress))
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Invalid DNS server address in configuration. Falling back to 8.8.8.8.");
                Console.ResetColor();
                dnsServerAddress = IPAddress.Parse("8.8.8.8");
            }

            if (response == "Y")
            {
                Console.Write("Enter the new DNS server IP address: ");
                string? dnsInput = Console.ReadLine()?.Trim();
                if (IPAddress.TryParse(dnsInput, out IPAddress? parsedAddress))
                {
                    dnsServerAddress = parsedAddress;
                    Console.WriteLine($"Using custom DNS server {dnsServerAddress}");
                }
                else
                {
                    Console.WriteLine("Invalid IP address. Using the configuration DNS server.");
                }
            }

            var perQueryTimeoutSeconds = configuration.GetValue("Timeouts:PerQuerySeconds", 5);
            if (perQueryTimeoutSeconds <= 0)
            {
                perQueryTimeoutSeconds = 5;
            }

            var perDomainTimeoutSeconds = configuration.GetValue("Timeouts:PerDomainSeconds", perQueryTimeoutSeconds + 2);
            if (perDomainTimeoutSeconds <= 0)
            {
                perDomainTimeoutSeconds = perQueryTimeoutSeconds + 2;
            }
            if (perDomainTimeoutSeconds < perQueryTimeoutSeconds)
            {
                perDomainTimeoutSeconds = perQueryTimeoutSeconds;
            }

            var perQueryTimeout = TimeSpan.FromSeconds(perQueryTimeoutSeconds);
            var perDomainTimeout = TimeSpan.FromSeconds(perDomainTimeoutSeconds);

            var maxParallelism = configuration.GetValue("Parallelism:MaxParallelism", 4);
            if (maxParallelism <= 0)
            {
                maxParallelism = 4;
            }

            var retryMaxAttempts = configuration.GetValue("Retries:MaxAttempts", 3);
            if (retryMaxAttempts <= 0)
            {
                retryMaxAttempts = 1;
            }

            var retryBaseDelayMilliseconds = configuration.GetValue("Retries:BaseDelayMilliseconds", 250);
            if (retryBaseDelayMilliseconds < 0)
            {
                retryBaseDelayMilliseconds = 0;
            }

            var resumeEnabled = configuration.GetValue("Resume:Enabled", true);
            var resumeCachePath = configuration.GetValue<string>("Resume:CachePath") ?? @"c:\techno\processed-domains.txt";

            // Set up DNS client with timeout
            var clientOptions = new LookupClientOptions(dnsServerAddress)
            {
                Timeout = perQueryTimeout,
                UseCache = true,
                Retries = 2
            };

            var client = new LookupClient(clientOptions);

            // Get target servers from configuration
            var targetNsServers = configuration.GetSection("TargetNsServers").Get<List<string>>() ??
                new List<string> { "ns1.technohosting.com.au", "ns2.technohosting.com.au" };

            // Use TargetARecords from configuration, falling back to defaults only if missing
            var targetARecords = configuration.GetSection("TargetARecords").Get<List<string>>() ??
                new List<string> { "103.116.1.1", "103.116.1.2", "103.116.1.4", "43.245.72.13" };

            var targetMxServers = configuration.GetSection("TargetMxServers").Get<List<string>>() ??
                new List<string> { "mail.protection.outlook.com", "mx1-us1.ppe-hosted.com", "mx2-us1.ppe-hosted.com" };

            // Main application loop
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Options:");
                Console.WriteLine("  i - Check individual domain (default)");
                Console.WriteLine("  d - Process domains from CSV file");
                Console.WriteLine("  q - Quit application");
                Console.Write("Enter your choice: ");
                
                var choice = Console.ReadLine()?.Trim().ToLowerInvariant();

                if (string.IsNullOrEmpty(choice) || choice == "i")
                {
                    await CheckIndividualDomain(client, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, perDomainTimeout, retryMaxAttempts, retryBaseDelayMilliseconds);
                }
                else if (choice == "d")
                {
                    await ProcessCsvFile(
                        client,
                        targetNsServers,
                        targetARecords,
                        targetMxServers,
                        perQueryTimeout,
                        perDomainTimeout,
                        retryMaxAttempts,
                        retryBaseDelayMilliseconds,
                        maxParallelism,
                        resumeEnabled,
                        resumeCachePath,
                        configuration);
                }
                else if (choice == "q")
                {
                    Console.WriteLine("Exiting program.");
                    break;
                }
                else
                {
                    Console.WriteLine("Invalid choice. Please enter 'i', 'd', or 'q'.");
                }
            }
        }
        catch (ArgumentException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Configuration error: {ex.Message}");
            Console.ResetColor();
        }
        catch (InvalidOperationException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Operation error: {ex.Message}");
            Console.ResetColor();
        }
        catch (IOException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"I/O error: {ex.Message}");
            Console.ResetColor();
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Access error: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static async Task<List<DomainCheckResult>> ProcessDomainBatchAsync(
        List<string> domains,
        LookupClient client,
        List<string> targetNsServers,
        List<string> targetARecords,
        List<string> targetMxServers,
        TimeSpan perQueryTimeout,
        TimeSpan perDomainTimeout,
        int retryMaxAttempts,
        int retryBaseDelayMilliseconds,
        int maxParallelism,
        bool updateResumeCache,
        string resumeCachePath,
        bool displayProgress)
    {
        var results = new ConcurrentBag<DomainCheckResult>();
        var total = domains.Count;
        var completed = 0;
        var parallelOptions = new ParallelOptions
        {
            MaxDegreeOfParallelism = maxParallelism
        };

        var progressLock = new object();
        var resumeLock = new object();

        await Parallel.ForEachAsync(domains, parallelOptions, async (domain, cancellationToken) =>
        {
            if (!TryNormalizeDomain(domain, out var normalizedDomain, out var errorMessage))
            {
                CheckAndMatchDomainHelper.AddBrokenDomain(domain);
                results.Add(new DomainCheckResult
                {
                    Domain = domain,
                    IsBroken = true,
                    ErrorReason = errorMessage
                });
                if (updateResumeCache)
                {
                    AppendResumeCache(resumeCachePath, domain, resumeLock);
                }
                UpdateProgress(displayProgress, ref completed, total, domain, progressLock);
                return;
            }

            try
            {
                using var domainCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                domainCts.CancelAfter(perDomainTimeout);
                var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(
                    client,
                    normalizedDomain,
                    targetNsServers,
                    targetARecords,
                    targetMxServers,
                    perQueryTimeout,
                    retryMaxAttempts,
                    retryBaseDelayMilliseconds,
                    domainCts.Token,
                    false,
                    0,
                    total).ConfigureAwait(false);
                results.Add(result);
            }
            catch (InvalidOperationException ex)
            {
                results.Add(new DomainCheckResult
                {
                    Domain = domain,
                    IsBroken = true,
                    ErrorReason = $"Exception: {ex.Message}"
                });
            }
            catch (OperationCanceledException ex)
            {
                results.Add(new DomainCheckResult
                {
                    Domain = domain,
                    IsBroken = true,
                    ErrorReason = $"Exception: {ex.Message}"
                });
            }
            finally
            {
                if (updateResumeCache)
                {
                    AppendResumeCache(resumeCachePath, domain, resumeLock);
                }
                UpdateProgress(displayProgress, ref completed, total, domain, progressLock);
            }
        }).ConfigureAwait(false);

        if (displayProgress)
        {
            lock (progressLock)
            {
                Console.WriteLine();
            }
        }

        return results.ToList();
    }

    private static void UpdateProgress(bool displayProgress, ref int completed, int total, string domain, object progressLock)
    {
        if (!displayProgress || total == 0)
        {
            return;
        }

        var current = Math.Min(Interlocked.Increment(ref completed), total);
        var barWidth = 30;
        var filled = (int)Math.Round(current / (double)total * barWidth);
        var bar = new string('#', filled).PadRight(barWidth, '-');
        var message = $"[{bar}] {current}/{total} {domain}";
        var consoleWidth = 0;

        try
        {
            consoleWidth = Console.WindowWidth;
        }
        catch
        {
            consoleWidth = 0;
        }

        lock (progressLock)
        {
            if (consoleWidth > 0)
            {
                var maxWidth = Math.Max(1, consoleWidth - 1);
                if (message.Length > maxWidth)
                {
                    message = message[..maxWidth];
                }
                message = message.PadRight(maxWidth);
                ProgressLineLength = maxWidth;
            }
            else
            {
                if (message.Length < ProgressLineLength)
                {
                    message = message.PadRight(ProgressLineLength);
                }
                ProgressLineLength = message.Length;
            }

            Console.Write($"\r{message}");
        }
    }

    private static async Task CheckIndividualDomain(LookupClient client, List<string> targetNsServers, List<string> targetARecords, List<string> targetMxServers, TimeSpan perQueryTimeout, TimeSpan perDomainTimeout, int retryMaxAttempts, int retryBaseDelayMilliseconds)
    {
        Console.Write("Enter the domain to check: ");
        var domainInput = Console.ReadLine();

        if (!TryNormalizeDomain(domainInput, out var domain, out var errorMessage))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(errorMessage);
            Console.ResetColor();
            return;
        }

        Console.WriteLine($"Checking individual domain: {domain}");
        
        try
        {
            using var domainCts = new CancellationTokenSource(perDomainTimeout);
            var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(client, domain, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, domainCts.Token, true, 1, 1);
            DisplayDomainResult(result, client);
        }
        catch (InvalidOperationException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error checking domain {domain}: {ex.Message}");
            Console.ResetColor();
        }
        catch (OperationCanceledException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error checking domain {domain}: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static void DisplayDomainResult(DomainCheckResult result, LookupClient client)
    {
        // Helper for wrapping long lines
        var wrapWidth = 120;
        try
        {
            wrapWidth = Math.Min(Console.WindowWidth, 120);
        }
        catch
        {
            wrapWidth = 120;
        }
        void WriteWrapped(string prefix, string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            var lines = new List<string>();
            while (text.Length > wrapWidth - prefix.Length)
            {
                lines.Add(text.Substring(0, wrapWidth - prefix.Length));
                text = text.Substring(wrapWidth - prefix.Length);
            }
            lines.Add(text);
            for (int i = 0; i < lines.Count; i++)
            {
                if (i == 0)
                    Console.WriteLine(prefix + lines[i]);
                else
                    Console.WriteLine(new string(' ', prefix.Length) + lines[i]);
            }
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"Domain: {result.Domain}");
        Console.ResetColor();

        if (result.IsBroken)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"DNS Error: {result.ErrorReason ?? "Unknown error"}");
            Console.ResetColor();
            return;
        }

        if (result.QueryErrors != null && result.QueryErrors.Count > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Query issues:");
            Console.ResetColor();
            foreach (var error in result.QueryErrors)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  {error}");
                Console.ResetColor();
            }
            Console.WriteLine();
        }

        // NS Records
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("NS Match: ");
        Console.ForegroundColor = result.NsMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(result.NsMatch);
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("NS Records:");
        Console.ResetColor();
        if (result.NsRecords != null && result.NsRecords.Count > 0)
        {
            foreach (var ns in result.NsRecords)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"  {ns}");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No NS records found");
            Console.ResetColor();
        }
        Console.WriteLine();

        // A Records
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("A Match: ");
        Console.ForegroundColor = result.AMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(result.AMatch);
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"A Records for {result.Domain}:");
        Console.ResetColor();
        if (result.ARecords != null && result.ARecords.Count > 0)
        {
            foreach (var ip in result.ARecords)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  {ip}");
                if (ServerNameHelper.ServerNames.TryGetValue(ip, out var serverName))
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($" (running on our {serverName})");
                }
                Console.ResetColor();
                Console.WriteLine();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No A records found");
            Console.ResetColor();
        }
        Console.WriteLine();

        // www A Records
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"A Records for www.{result.Domain}:");
        Console.ResetColor();
        try
        {
            var wwwResponse = client.Query($"www.{result.Domain}", QueryType.A);
            var wwwARecords = wwwResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();
            if (wwwARecords.Count > 0)
            {
                foreach (var ip in wwwARecords)
                {
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"  {ip}");
                    if (ServerNameHelper.ServerNames.TryGetValue(ip, out var serverName))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write($" (running on our {serverName})");
                    }
                    Console.ResetColor();
                    Console.WriteLine();
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  No A records found for www.{result.Domain}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  Error querying A records for www.{result.Domain}: {ex.Message}");
            Console.ResetColor();
        }
        Console.WriteLine();

        // MX Records
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("MX Match: ");
        Console.ForegroundColor = result.MxMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine(result.MxMatch);
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("MX Records:");
        Console.ResetColor();
        if (result.MxRecords != null && result.MxRecords.Count > 0)
        {
            foreach (var mxRecord in result.MxRecords)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"  {mxRecord}");
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  No MX records found");
            Console.ResetColor();
        }
        Console.WriteLine();

        // SPF Record
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("SPF Record:");
        Console.ResetColor();
        if (!string.IsNullOrEmpty(result.SpfRecord))
        {
            Console.Write("  Valid: ");
            Console.ForegroundColor = result.SpfValid ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine(result.SpfValid);
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.White;
            WriteWrapped("  Record: ", $"{result.SpfRecord}");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  No SPF record found.");
            Console.ResetColor();
        }
        Console.WriteLine();

        // DMARC Record
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("DMARC Record:");
        Console.ResetColor();
        if (!string.IsNullOrEmpty(result.DmarcRecord))
        {
            Console.Write("  Valid: ");
            Console.ForegroundColor = result.DmarcValid ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine(result.DmarcValid);
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.White;
            WriteWrapped("  Record: ", $"{result.DmarcRecord}");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  No DMARC record found.");
            Console.ResetColor();
        }
        Console.WriteLine();

        // DKIM Records
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("DKIM Records:");
        Console.ResetColor();
        if (result.DkimSelectorResults != null && result.DkimSelectorResults.Count > 0)
        {
            foreach (var kvp in result.DkimSelectorResults)
            {
                var selector = kvp.Key;
                var value = kvp.Value.Value;
                var isValid = kvp.Value.IsValid;
                Console.Write($"  {selector}: ");
                Console.ForegroundColor = isValid ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(isValid ? "Valid" : "Not valid");
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.White;
                WriteWrapped("    ", value);
                Console.ResetColor();
            }
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("  No DKIM records found.");
            Console.ResetColor();
        }
        Console.WriteLine();

        // Summary Section
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("---------------------");
        Console.WriteLine("Summary:");
        Console.ResetColor();
        if (result.NsMatch && result.AMatch && result.MxMatch && result.SpfValid && result.DmarcValid && result.DkimValid)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  All checks passed.");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            if (!result.NsMatch) Console.WriteLine("  NS mismatch.");
            if (!result.AMatch) Console.WriteLine("  A record mismatch.");
            if (!result.MxMatch) Console.WriteLine("  MX mismatch.");
            if (!result.SpfValid) Console.WriteLine("  SPF record invalid or missing.");
            if (!result.DmarcValid) Console.WriteLine("  DMARC record invalid or missing.");
            if (!result.DkimValid) Console.WriteLine("  DKIM record invalid or missing.");
        }
        Console.ResetColor();
        Console.WriteLine("---------------------");
    }

    private static async Task ProcessCsvFile(
        LookupClient client,
        List<string> targetNsServers,
        List<string> targetARecords,
        List<string> targetMxServers,
        TimeSpan perQueryTimeout,
        TimeSpan perDomainTimeout,
        int retryMaxAttempts,
        int retryBaseDelayMilliseconds,
        int maxParallelism,
        bool resumeEnabled,
        string resumeCachePath,
        IConfiguration configuration)
    {
        try
        {
            // Get CSV file paths from configuration
            string inputFilePath = configuration.GetSection("CsvPaths:Input").Value ?? @"c:\techno\domains.csv";
            string outputFilePath = configuration.GetSection("CsvPaths:Output").Value ?? @"c:\techno\results.csv";

            // Ensure directories exist
            var outputDir = Path.GetDirectoryName(outputFilePath);
                if (!string.IsNullOrEmpty(outputDir))
                    {
                    Directory.CreateDirectory(outputDir);
                    }

            List<string> domains = ReadDomainFromCsvHelper.ReadDomainsFromCsv(inputFilePath);
            
            if (domains.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("No domains found to process.");
                Console.ResetColor();
                return;
            }

            var useResume = resumeEnabled;
            if (resumeEnabled)
            {
                Console.WriteLine(Strings.ResumePrompt);
                var resumeResponse = Console.ReadLine()?.Trim().ToUpperInvariant();
                if (resumeResponse == "N")
                {
                    useResume = false;
                    ClearResumeCache(resumeCachePath);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(Strings.ResumeCacheClearedMessage);
                    Console.ResetColor();
                }
            }

            var processedDomains = useResume ? LoadResumeCache(resumeCachePath) : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var remainingDomains = domains.Where(domain => !processedDomains.Contains(domain)).ToList();

            if (useResume && remainingDomains.Count != domains.Count)
            {
                Console.WriteLine($"Skipping {domains.Count - remainingDomains.Count} domains already processed.");
            }

            if (useResume && remainingDomains.Count == 0)
            {
                Console.WriteLine(Strings.ResumeAllProcessedPrompt);
                var resumeResponse = Console.ReadLine()?.Trim().ToUpperInvariant();
                if (resumeResponse == "Y")
                {
                    remainingDomains = domains;
                    ClearResumeCache(resumeCachePath);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine(Strings.ResumeCacheClearedMessage);
                    Console.ResetColor();
                }
                else
                {
                    Console.WriteLine(Strings.NoDomainsToProcessMessage);
                    return;
                }
            }

            Console.WriteLine($"Processing {remainingDomains.Count} domains...");
            // Clear broken domains list before starting new batch
            CheckAndMatchDomainHelper.ClearBrokenDomains();

            var results = await ProcessDomainBatchAsync(
                remainingDomains,
                client,
                targetNsServers,
                targetARecords,
                targetMxServers,
                perQueryTimeout,
                perDomainTimeout,
                retryMaxAttempts,
                retryBaseDelayMilliseconds,
                maxParallelism,
                useResume,
                resumeCachePath,
                true).ConfigureAwait(false);

            Console.WriteLine();
            Console.WriteLine($"Completed processing {remainingDomains.Count} domains.");

            // Display summary of issues found
            CheckAndMatchDomainHelper.DisplayBrokenDomains();

            // Export results to CSV
            Console.WriteLine("Writing results to CSV...");
            ExportToCsvHelper.ExportResultsToCsv(outputFilePath, results, append: false);
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Results saved to: {outputFilePath}");
            Console.ResetColor();

            var failedDomains = results.Where(result => result.IsBroken && !string.IsNullOrWhiteSpace(result.Domain))
                .Select(result => result.Domain!)
                .ToList();
            if (failedDomains.Count > 0)
            {
                Console.WriteLine(Strings.RetryFailedPrompt);
                var retryResponse = Console.ReadLine()?.Trim().ToUpperInvariant();
                if (retryResponse == "Y")
                {
                    var retryResults = await ProcessDomainBatchAsync(
                        failedDomains,
                        client,
                        targetNsServers,
                        targetARecords,
                        targetMxServers,
                        perQueryTimeout,
                        perDomainTimeout,
                        retryMaxAttempts,
                        retryBaseDelayMilliseconds,
                        maxParallelism,
                        false,
                        resumeCachePath,
                        true).ConfigureAwait(false);

                    ExportToCsvHelper.ExportResultsToCsv(outputFilePath, retryResults, append: true);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(string.Format(Strings.RetryAppendedMessageFormat, outputFilePath));
                    Console.ResetColor();
                }
            }
        }
        catch (IOException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error processing CSV file: {ex.Message}");
            Console.ResetColor();
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error processing CSV file: {ex.Message}");
            Console.ResetColor();
        }
        catch (InvalidOperationException ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error processing CSV file: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static void ClearResumeCache(string cachePath)
    {
        try
        {
            if (File.Exists(cachePath))
            {
                File.Delete(cachePath);
            }
        }
        catch (IOException ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Unable to clear resume cache: {ex.Message}");
            Console.ResetColor();
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Unable to clear resume cache: {ex.Message}");
            Console.ResetColor();
        }
    }

    private static HashSet<string> LoadResumeCache(string cachePath)
    {
        try
        {
            if (!File.Exists(cachePath))
            {
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            var lines = File.ReadAllLines(cachePath);
            return new HashSet<string>(lines.Where(line => !string.IsNullOrWhiteSpace(line)).Select(line => line.Trim()), StringComparer.OrdinalIgnoreCase);
        }
        catch (IOException ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Unable to read resume cache: {ex.Message}");
            Console.ResetColor();
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Unable to read resume cache: {ex.Message}");
            Console.ResetColor();
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static void AppendResumeCache(string cachePath, string domain, object resumeLock)
    {
        lock (resumeLock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(cachePath) ?? Directory.GetCurrentDirectory());
                File.AppendAllLines(cachePath, new[] { domain });
            }
            catch (IOException ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Unable to update resume cache: {ex.Message}");
                Console.ResetColor();
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Unable to update resume cache: {ex.Message}");
                Console.ResetColor();
            }
        }
    }

    private static bool TryNormalizeDomain(string? input, out string normalizedDomain, out string errorMessage)
    {
        normalizedDomain = string.Empty;
        errorMessage = string.Empty;

        if (string.IsNullOrWhiteSpace(input))
        {
            errorMessage = "No domain entered.";
            return false;
        }

        var trimmed = input.Trim().TrimEnd('.');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            errorMessage = "No domain entered.";
            return false;
        }

        string asciiDomain;
        try
        {
            asciiDomain = new IdnMapping().GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            errorMessage = "Invalid domain format.";
            return false;
        }

        if (Uri.CheckHostName(asciiDomain) != UriHostNameType.Dns)
        {
            errorMessage = "Invalid domain format.";
            return false;
        }

        normalizedDomain = asciiDomain.ToLowerInvariant();
        return true;
    }
}