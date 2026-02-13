using DnsChecker.Entities;
using DnsChecker.Helpers;
using DnsClient;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace DnsChecker;

public static class Program
{
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
            string? response = Console.ReadLine()?.Trim().ToUpper();

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
                
                var choice = Console.ReadLine()?.Trim().ToLower();

                if (string.IsNullOrEmpty(choice) || choice == "i")
                {
                    await CheckIndividualDomain(client, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, perDomainTimeout);
                }
                else if (choice == "d")
                {
                    await ProcessCsvFile(client, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, perDomainTimeout, configuration);
                }
                else if (choice == "q")
                {
                    Console.WriteLine("Exiting program.");
                    break; // Exits the while loop and ends the program
                }
                else
                {
                    Console.WriteLine("Invalid choice. Please enter 'i', 'd', or 'q'.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Unhandled exception: {ex.Message}");
            Console.ResetColor();
        }
        finally
        {
        }
    }

    private static async Task CheckIndividualDomain(LookupClient client, List<string> targetNsServers, List<string> targetARecords, List<string> targetMxServers, TimeSpan perQueryTimeout, TimeSpan perDomainTimeout)
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
            var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(client, domain, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, domainCts.Token);
            DisplayDomainResult(result, client);
        }
        catch (Exception ex)
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

    private static async Task ProcessCsvFile(LookupClient client, List<string> targetNsServers, List<string> targetARecords, List<string> targetMxServers, TimeSpan perQueryTimeout, TimeSpan perDomainTimeout, IConfiguration configuration)
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

            Console.WriteLine($"Processing {domains.Count} domains...");
            List<DomainCheckResult> results = new List<DomainCheckResult>();
            int current = 0;
            int total = domains.Count;

            // Clear broken domains list before starting new batch
            CheckAndMatchDomainHelper.ClearBrokenDomains();

            foreach (var domain in domains)
            {
                current++;
                Console.Write($"\rProcessing domain {current}/{total}: {domain.PadRight(30)}");

                if (!TryNormalizeDomain(domain, out var normalizedDomain, out var errorMessage))
                {
                    CheckAndMatchDomainHelper.BrokenDomains.Add(domain);
                    results.Add(new DomainCheckResult
                    {
                        Domain = domain,
                        IsBroken = true,
                        ErrorReason = errorMessage
                    });
                    continue;
                }
                
                try
                {
                    using var domainCts = new CancellationTokenSource(perDomainTimeout);
                    var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(client, normalizedDomain, targetNsServers, targetARecords, targetMxServers, perQueryTimeout, domainCts.Token);
                    results.Add(result);
                }
                catch (Exception ex)
                {
                    // Create a result for the failed domain
                    results.Add(new DomainCheckResult
                    {
                        Domain = domain,
                        IsBroken = true,
                        ErrorReason = $"Exception: {ex.Message}"
                    });
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Completed processing {domains.Count} domains.");

            // Display summary of issues found
            CheckAndMatchDomainHelper.DisplayBrokenDomains();

            // Export results to CSV
            Console.WriteLine("Writing results to CSV...");
            ExportToCsvHelper.ExportResultsToCsv(outputFilePath, results);
            
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Results saved to: {outputFilePath}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error processing CSV file: {ex.Message}");
            Console.ResetColor();
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