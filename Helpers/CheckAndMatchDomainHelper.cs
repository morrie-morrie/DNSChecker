using DnsChecker.Entities;
using DnsClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DnsChecker.Helpers;

/// <summary>
/// Helper class for checking DNS records of domains and comparing them with target servers.
/// </summary>
internal static class CheckAndMatchDomainHelper
{
    private static readonly List<string> BrokenDomains = new();
    private static readonly object BrokenDomainsLock = new();

    // This is a static class - no need for constructor comment

    /// <summary>
    /// Checks DNS records for a domain and compares against target servers.
    /// </summary>
    /// <param name="client">The DNS lookup client to use for queries</param>
    /// <param name="domain">Domain name to check</param>
    /// <param name="targetNs">List of target nameserver hostnames to match against</param>
    /// <param name="targetA">List of target IP addresses to match against</param>
    /// <param name="targetMx">Optional list of target MX servers to match against</param>
    /// <param name="perQueryTimeout">Timeout applied to each DNS query</param>
    /// <param name="retryMaxAttempts">Maximum retry attempts for transient DNS failures</param>
    /// <param name="retryBaseDelayMilliseconds">Base delay for exponential backoff retries</param>
    /// <param name="cancellationToken">Cancellation token for the overall domain check</param>
    /// <param name="displayProgress">Whether to display progress output for the domain</param>
    /// <param name="itemNumber">Current item number for progress display</param>
    /// <param name="totalItems">Total items for progress display</param>
    /// <returns>A DomainCheckResult containing the detailed results of the domain check</returns>
    public static async Task<DomainCheckResult> CheckAndMatchDomain(
        LookupClient client, 
        string domain, 
        List<string> targetNs, 
        List<string> targetA, 
        List<string>? targetMx,
        TimeSpan perQueryTimeout,
        int retryMaxAttempts,
        int retryBaseDelayMilliseconds,
        CancellationToken cancellationToken,
        bool displayProgress,
        int itemNumber,
        int totalItems)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentException("Domain cannot be empty", nameof(domain));
        ArgumentNullException.ThrowIfNull(targetNs);
        ArgumentNullException.ThrowIfNull(targetA);
        if (perQueryTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(perQueryTimeout));
        if (retryMaxAttempts <= 0) throw new ArgumentOutOfRangeException(nameof(retryMaxAttempts));
        if (retryBaseDelayMilliseconds < 0) throw new ArgumentOutOfRangeException(nameof(retryBaseDelayMilliseconds));

        domain = domain.Trim().ToLowerInvariant();
        if (displayProgress)
        {
            DisplayCurrentDomain(domain, itemNumber, totalItems);
        }

        var result = new DomainCheckResult
        {
            Domain = domain,
            NsRecords = new List<string>(),
            ARecords = new List<string>(),
            MxRecords = new List<string>(),
            QueryErrors = new List<string>(),
            IsBroken = false
        };

        try
        {
            // Execute DNS queries in parallel for better performance
            var queries = new[]
            {
                ExecuteQueryAsync(client, domain, QueryType.NS, "NS", perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, cancellationToken),
                ExecuteQueryAsync(client, domain, QueryType.A, "A", perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, cancellationToken),
                ExecuteQueryAsync(client, domain, QueryType.MX, "MX", perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, cancellationToken),
                ExecuteQueryAsync(client, domain, QueryType.TXT, "SPF", perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, cancellationToken),
                ExecuteQueryAsync(client, $"_dmarc.{domain}", QueryType.TXT, "DMARC", perQueryTimeout, retryMaxAttempts, retryBaseDelayMilliseconds, cancellationToken)
            };

            // Wait for all queries to complete
            var responses = await Task.WhenAll(queries).ConfigureAwait(false);

            foreach (var response in responses)
            {
                if (!string.IsNullOrWhiteSpace(response.Error))
                {
                    result.QueryErrors.Add(response.Error);
                }
            }

            var nsResponse = responses[0].Response;
            var aResponse = responses[1].Response;
            var mxResponse = responses[2].Response;
            var txtResponse = responses[3].Response;
            var dmarcResponse = responses[4].Response;

            // Process SPF records
            if (txtResponse != null)
            {
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
                result.SpfValid = !string.IsNullOrEmpty(result.SpfRecord) &&
                                 (result.SpfRecord.EndsWith("-all", StringComparison.OrdinalIgnoreCase) ||
                                  result.SpfRecord.EndsWith("~all", StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                result.SpfRecord = null;
                result.SpfValid = false;
            }

            // Process DMARC record
            if (dmarcResponse != null)
            {
                var dmarcTxt = dmarcResponse.Answers.TxtRecords().SelectMany(txt => txt.Text)
                    .FirstOrDefault(t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
                result.DmarcRecord = dmarcTxt;
                result.DmarcValid = !string.IsNullOrEmpty(dmarcTxt) && dmarcTxt.Contains("p=", StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                result.DmarcRecord = null;
                result.DmarcValid = false;
            }

            // Process DKIM records (try common selectors)
            var commonSelectors = new[] { "default", "selector1", "selector2", "dkim", "google", "mail", "smtp", "key1", "key2" };
            var dkimSelectors = new List<string>();
            var dkimValid = false;
            var dkimSelectorResults = new Dictionary<string, (string Value, bool IsValid)>();
            foreach (var selector in commonSelectors)
            {
                var dkimResult = await ExecuteQueryAsync(
                    client,
                    $"{selector}._domainkey.{domain}",
                    QueryType.TXT,
                    $"DKIM ({selector})",
                    perQueryTimeout,
                    retryMaxAttempts,
                    retryBaseDelayMilliseconds,
                    cancellationToken).ConfigureAwait(false);

                if (!string.IsNullOrWhiteSpace(dkimResult.Error))
                {
                    result.QueryErrors.Add(dkimResult.Error);
                    continue;
                }

                var dkimQuery = dkimResult.Response;
                if (dkimQuery == null)
                {
                    continue;
                }

                foreach (var txt in dkimQuery.Answers.TxtRecords())
                {
                    foreach (var text in txt.Text)
                    {
                        if (text.StartsWith("v=DKIM1", StringComparison.OrdinalIgnoreCase))
                        {
                            dkimSelectors.Add(selector);
                            bool isValid = text.Contains("p=", StringComparison.OrdinalIgnoreCase);
                            if (isValid) dkimValid = true;
                            dkimSelectorResults[selector] = (text, isValid);
                        }
                    }
                }
            }
            result.DkimRecords = dkimSelectors;
            result.DkimValid = dkimValid;
            result.DkimSelectorResults = dkimSelectorResults;

            // Process records
            result.NsRecords = nsResponse?.Answers.NsRecords()
                .Select(r => r.NSDName.Value.TrimEnd('.').ToLowerInvariant())
                .ToList() ?? new List<string>();
            
            result.ARecords = aResponse?.Answers.ARecords()
                .Select(r => r.Address.ToString())
                .ToList() ?? new List<string>();
            
            result.MxRecords = mxResponse?.Answers.MxRecords()
                .Select(r => r.Exchange.Value.ToLowerInvariant().TrimEnd('.'))
                .ToList() ?? new List<string>();

            // Check for matches with target servers
            result.NsMatch = targetNs.Any(ns => result.NsRecords.Contains(ns.ToLowerInvariant()));

            // Normalize and deduplicate A records and targets (treat IPv4 strings case-insensitively even though case doesn't matter)
            var normalizedTargetA = new HashSet<string>(targetA.Select(ip => ip.Trim()), StringComparer.OrdinalIgnoreCase);
            var normalizedARecords = new HashSet<string>(result.ARecords.Select(ip => ip.Trim()), StringComparer.OrdinalIgnoreCase);
            result.AMatch = normalizedARecords.Overlaps(normalizedTargetA);
            
            // Add MX matching if target MX servers are provided
            if (targetMx != null && targetMx.Count > 0)
            {
                var normalizedTargetMx = targetMx.Select(mx => mx.ToLowerInvariant().TrimEnd('.')).ToList();
                // Check if any MX record contains any target MX substring
                result.MxMatch = result.MxRecords.Any(mxRecord => normalizedTargetMx.Any(target => mxRecord.Contains(target)));
            }
        }
        catch (DnsResponseException ex)
        {
            Log.Error(ex, "DNS query failed for {domain}. Status: {errorCode}", domain, ex.Code);
            result.IsBroken = true;
            result.ErrorReason = $"DNS query failed: {ex.Message}";
            AddBrokenDomain(domain);
        }
        catch (OperationCanceledException ex)
        {
            Log.Error(ex, "DNS query timed out for {domain}.", domain);
            result.IsBroken = true;
            result.ErrorReason = "DNS query timed out";
            AddBrokenDomain(domain);
        }
        return result;
    }

    private static async Task<QueryResult> ExecuteQueryAsync(
        LookupClient client,
        string queryName,
        QueryType queryType,
        string queryLabel,
        TimeSpan timeout,
        int retryMaxAttempts,
        int retryBaseDelayMilliseconds,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= retryMaxAttempts; attempt++)
        {
            var queryTask = client.QueryAsync(queryName, queryType);
            var delayTask = Task.Delay(timeout, cancellationToken);

            var completedTask = await Task.WhenAny(queryTask, delayTask).ConfigureAwait(false);
            if (completedTask == delayTask)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (attempt == retryMaxAttempts)
                {
                    Log.Warning("DNS query timed out for {queryLabel} on {domain}.", queryLabel, queryName);
                    return new QueryResult(null, $"{queryLabel} query timed out");
                }
            }
            else
            {
                try
                {
                    var response = await queryTask.ConfigureAwait(false);
                    return new QueryResult(response, null);
                }
                catch (DnsResponseException ex)
                {
                    Log.Warning(ex, "DNS query failed for {queryLabel} on {domain}. Status: {errorCode}", queryLabel, queryName, ex.Code);
                    if (attempt == retryMaxAttempts)
                    {
                        return new QueryResult(null, $"{queryLabel} query failed: {ex.Message}");
                    }
                }
                catch (InvalidOperationException ex)
                {
                    Log.Warning(ex, "DNS query failed for {queryLabel} on {domain}.", queryLabel, queryName);
                    if (attempt == retryMaxAttempts)
                    {
                        return new QueryResult(null, $"{queryLabel} query failed: {ex.Message}");
                    }
                }
                catch (SocketException ex)
                {
                    Log.Warning(ex, "DNS query failed for {queryLabel} on {domain}.", queryLabel, queryName);
                    if (attempt == retryMaxAttempts)
                    {
                        return new QueryResult(null, $"{queryLabel} query failed: {ex.Message}");
                    }
                }
                catch (TimeoutException ex)
                {
                    Log.Warning(ex, "DNS query failed for {queryLabel} on {domain}.", queryLabel, queryName);
                    if (attempt == retryMaxAttempts)
                    {
                        return new QueryResult(null, $"{queryLabel} query failed: {ex.Message}");
                    }
                }
            }

            if (retryBaseDelayMilliseconds > 0)
            {
                var delay = TimeSpan.FromMilliseconds(retryBaseDelayMilliseconds * Math.Pow(2, attempt - 1));
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        return new QueryResult(null, $"{queryLabel} query failed");
    }

    private readonly record struct QueryResult(IDnsQueryResponse? Response, string? Error);

    /// <summary>
    /// Displays the current domain being checked in the console.
    /// </summary>
    /// <param name="domain">Domain name to display</param>
    /// <param name="itemNumber">Current item number for progress display</param>
    /// <param name="totalItems">Total items for progress display</param>
    public static void DisplayCurrentDomain(string domain, int itemNumber, int totalItems)
    {
        try
        {
            // Reset color for the prefix text
            Console.ResetColor();
            var prefix = $"Checking domain {itemNumber}/{totalItems}: ";
            Console.Write("\r" + prefix);

            // Set color to light blue for the domain name
            Console.ForegroundColor = ConsoleColor.Cyan;
            
            // Get console width safely
            int consoleWidth = 80;
            try { consoleWidth = Console.WindowWidth; } catch { /* Use default width if console width isn't available */ }
            
            var availableWidth = Math.Max(1, consoleWidth - prefix.Length - 1);
            Console.Write(domain.PadRight(availableWidth));

            // Reset color back to default after writing the domain
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            // Fallback display if console operations fail
            Console.WriteLine($"Checking domain {itemNumber}/{totalItems}: {domain}");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Warning: Error when displaying domain in console: {ex.Message}");
            Console.ResetColor();
        }
    }

    /// <summary>
    /// Adds a domain to the broken domain list.
    /// </summary>
    /// <param name="domain">Domain name to add</param>
    public static void AddBrokenDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            throw new ArgumentException("Domain cannot be empty", nameof(domain));
        }
        lock (BrokenDomainsLock)
        {
            BrokenDomains.Add(domain);
        }
    }

    /// <summary>
    /// Displays a list of domains where DNS queries failed or timed out.
    /// </summary>
    public static void DisplayBrokenDomains()
    {
        List<string> snapshot;
        lock (BrokenDomainsLock)
        {
            snapshot = BrokenDomains.ToList();
        }

        if (snapshot.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("\nDomains where DNS query failed or timed out:");
            foreach (var domain in snapshot)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(domain);
                Console.ResetColor();
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"Found {snapshot.Count} domains with DNS query failures");
            Console.ResetColor();
        }
        else
        {
            Console.WriteLine("\nThere were no domains with failed or timed out DNS queries.");
        }
    }
    
    /// <summary>
    /// Resets the list of broken domains.
    /// </summary>
    public static void ClearBrokenDomains()
    {
        lock (BrokenDomainsLock)
        {
            BrokenDomains.Clear();
        }
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("Cleared the list of broken domains");
        Console.ResetColor();
    }
}