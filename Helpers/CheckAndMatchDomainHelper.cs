using DnsChecker.Entities;
using DnsClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DnsChecker.Helpers;

/// <summary>
/// Helper class for checking DNS records of domains and comparing them with target servers.
/// </summary>
internal static class CheckAndMatchDomainHelper
{
    /// <summary>
    /// List of domains where DNS queries failed or timed out.
    /// </summary>
    internal static readonly List<string> BrokenDomains = new();

    // This is a static class - no need for constructor comment

    /// <summary>
    /// Checks DNS records for a domain and compares against target servers.
    /// </summary>
    /// <param name="client">The DNS lookup client to use for queries</param>
    /// <param name="domain">Domain name to check</param>
    /// <param name="targetNs">List of target nameserver hostnames to match against</param>
    /// <param name="targetA">List of target IP addresses to match against</param>
    /// <returns>A DomainCheckResult containing the detailed results of the domain check</returns>
    public static async Task<DomainCheckResult> CheckAndMatchDomain(LookupClient client, string domain, List<string> targetNs, List<string> targetA, List<string> targetMx = null)
    {
        if (client == null) throw new ArgumentNullException(nameof(client));
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentException("Domain cannot be empty", nameof(domain));
        if (targetNs == null) throw new ArgumentNullException(nameof(targetNs));
        if (targetA == null) throw new ArgumentNullException(nameof(targetA));

        domain = domain.Trim().ToLowerInvariant();
        DisplayCurrentDomain(domain);

        var result = new DomainCheckResult
        {
            Domain = domain,
            NsRecords = new List<string>(),
            ARecords = new List<string>(),
            MxRecords = new List<string>(),
            IsBroken = false
        };

        try
        {
            // Execute DNS queries in parallel for better performance
            var queries = new Task<IDnsQueryResponse>[] {
                client.QueryAsync(domain, QueryType.NS),
                client.QueryAsync(domain, QueryType.A),
                client.QueryAsync(domain, QueryType.MX),
                client.QueryAsync(domain, QueryType.TXT)
            };

            // Wait for all queries to complete
            var responses = await Task.WhenAll(queries);

            var nsResponse = responses[0];
            var aResponse = responses[1];
            var mxResponse = responses[2];
            var txtResponse = responses[3];

            // Process SPF records
            var spfParts = txtResponse.Answers.TxtRecords()
                .SelectMany(txt => txt.Text)
                .Where(txt => txt.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase) || 
                              txt.Contains("include:", StringComparison.OrdinalIgnoreCase) || 
                              txt.Contains("ip4:", StringComparison.OrdinalIgnoreCase) || 
                              txt.Contains("ip6:", StringComparison.OrdinalIgnoreCase) || 
                              txt.EndsWith("-all", StringComparison.OrdinalIgnoreCase) || 
                              txt.EndsWith("~all", StringComparison.OrdinalIgnoreCase) || 
                              txt.EndsWith("+all", StringComparison.OrdinalIgnoreCase) || 
                              txt.EndsWith("?all", StringComparison.OrdinalIgnoreCase))
                .ToList();

            result.SpfRecord = string.Join("", spfParts);
            
            // Improved SPF validation - consider both -all (strict) and ~all (soft fail) as valid practices
            result.SpfValid = !string.IsNullOrEmpty(result.SpfRecord) && 
                             (result.SpfRecord.EndsWith("-all", StringComparison.OrdinalIgnoreCase) || 
                              result.SpfRecord.EndsWith("~all", StringComparison.OrdinalIgnoreCase));

            // Process records
            result.NsRecords = nsResponse.Answers.NsRecords()
                .Select(r => r.NSDName.Value.TrimEnd('.').ToLowerInvariant())
                .ToList();
            
            result.ARecords = aResponse.Answers.ARecords()
                .Select(r => r.Address.ToString())
                .ToList();
            
            result.MxRecords = mxResponse.Answers.MxRecords()
                .Select(r => r.Exchange.Value.ToLowerInvariant().TrimEnd('.'))
                .ToList();

            // Check for matches with target servers
            result.NsMatch = targetNs.Any(ns => result.NsRecords.Contains(ns.ToLowerInvariant()));
            result.AMatch = targetA.Any(ip => result.ARecords.Contains(ip));
            
            // Add MX matching if target MX servers are provided
            if (targetMx != null && targetMx.Count > 0)
            {
                var normalizedTargetMx = targetMx.Select(mx => mx.ToLowerInvariant().TrimEnd('.')).ToList();
                result.MxMatch = normalizedTargetMx.Any(mx => result.MxRecords.Contains(mx));
            }
        }
        catch (DnsResponseException ex)
        {
            Log.Error(ex, "DNS query failed for {domain}. Status: {errorCode}", domain, ex.Code);
            result.IsBroken = true;
            result.ErrorReason = $"DNS query failed: {ex.Message}";
            BrokenDomains.Add(domain);
        }
        catch (OperationCanceledException ex)
        {
            Log.Error(ex, "DNS query timed out for {domain}.", domain);
            result.IsBroken = true;
            result.ErrorReason = "DNS query timed out";
            BrokenDomains.Add(domain);
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Unexpected error occurred for {domain}", domain);
            result.IsBroken = true;
            result.ErrorReason = $"Unexpected error: {ex.Message}";
            BrokenDomains.Add(domain);
        }
        return result;
    }

    /// <summary>
    /// Displays the current domain being checked in the console.
    /// </summary>
    /// <param name="domain">Domain name to display</param>
    public static void DisplayCurrentDomain(string domain)
    {
        try
        {
            // Reset color for the prefix text
            Console.ResetColor();
            Console.Write("\rChecking domain: ");

            // Set color to light blue for the domain name
            Console.ForegroundColor = ConsoleColor.Cyan;
            
            // Get console width safely
            int consoleWidth = 80;
            try { consoleWidth = Console.WindowWidth; } catch { /* Use default width if console width isn't available */ }
            
            Console.Write(domain.PadRight(consoleWidth - "Checking domain: ".Length - 1));

            // Reset color back to default after writing the domain
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            // Fallback display if console operations fail
            Console.WriteLine($"Checking domain: {domain}");
            Log.Warning(ex, "Error when displaying domain in console");
        }
    }

    /// <summary>
    /// Displays a list of domains where DNS queries failed or timed out.
    /// </summary>
    public static void DisplayBrokenDomains()
    {
        if (BrokenDomains.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("\nDomains where DNS query failed or timed out:");
            foreach (var domain in BrokenDomains)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(domain);
                Console.ResetColor();
            }
            
            Log.Warning("Found {count} domains with DNS query failures", BrokenDomains.Count);
        }
        else
        {
            Console.WriteLine("\nThere were no domains with failed or timed out DNS queries.");
            Log.Information("No domains with DNS query failures");
        }
    }
    
    /// <summary>
    /// Resets the list of broken domains.
    /// </summary>
    public static void ClearBrokenDomains()
    {
        BrokenDomains.Clear();
        Log.Information("Cleared the list of broken domains");
    }
}