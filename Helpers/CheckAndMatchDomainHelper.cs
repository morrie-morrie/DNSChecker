using DnsChecker.Entities;
using DnsClient;
using Serilog;

namespace DNSChecker.Helpers;

internal class CheckAndMatchDomainHelper
{
    public static List<string> BrokenDomains = new List<string>();

    public static async Task<DomainCheckResult> CheckAndMatchDomain(LookupClient client, string domain, List<string> targetNs, List<string> targetA)
    {
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
            var queries = new Task<IDnsQueryResponse>[] {
            client.QueryAsync(domain, QueryType.NS),
            client.QueryAsync(domain, QueryType.A),
            client.QueryAsync(domain, QueryType.MX),
            client.QueryAsync(domain, QueryType.TXT)
        };

            var responses = await Task.WhenAll(queries);

            var nsResponse = responses[0];
            var aResponse = responses[1];
            var mxResponse = responses[2];
            var txtResponse = responses[3];

            var spfParts = txtResponse.Answers.TxtRecords()
                .SelectMany(txt => txt.Text)
                .Where(txt => txt.StartsWith("v=spf1") || txt.Contains("include:") || txt.Contains("ip4:") || txt.Contains("ip6:") || txt.EndsWith("-all") || txt.EndsWith("~all") || txt.EndsWith("+all") || txt.EndsWith("?all"))
                .ToList();

            result.SpfRecord = string.Join("", spfParts);
            result.SpfValid = result.SpfRecord?.EndsWith("-all") ?? false;

            result.NsRecords = nsResponse.Answers.NsRecords().Select(r => r.NSDName.Value.TrimEnd('.')).ToList();
            result.ARecords = aResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();
            result.MxRecords = mxResponse.Answers.MxRecords().Select(r => r.Exchange.Value.ToLower().TrimEnd('.')).ToList();

            result.NsMatch = targetNs.Intersect(result.NsRecords).Any();
            result.AMatch = targetA.Intersect(result.ARecords).Any();
        }
        catch (DnsResponseException ex)
        {
            Log.Error(ex, $"DNS query failed for {domain}.");
            result.IsBroken = true;  // Indicate that DNS query failed for this domain
            BrokenDomains.Add(domain);
        }
        catch (OperationCanceledException ex)
        {
            Log.Error(ex, $"DNS query timed out for {domain}.");
            result.IsBroken = true; // Indicate that DNS query timed out for this domain
            BrokenDomains.Add(domain);
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Unexpected error occurred for {domain}");
            result.IsBroken = true;  // Indicate that there was an unexpected error
            BrokenDomains.Add(domain);
        }
        return result;
    }

    public static void DisplayCurrentDomain(string domain)
    {
        // Reset color for the prefix text
        Console.ResetColor();
        Console.Write("\rChecking domain: ");

        // Set color to light blue for the domain name
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write(domain.PadRight(Console.WindowWidth - "Checking domain: ".Length - 1));

        // Reset color back to default after writing the domain
        Console.ResetColor();
    }

    public static void DisplayBrokenDomains()
    {
        if (BrokenDomains.Any())
        {
            Console.WriteLine();
            Console.WriteLine("\nDomains where DNS query failed or timed out:");
            foreach (var domain in BrokenDomains)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(domain);
                Console.ResetColor();
            }
        }
        else
        {
            Console.WriteLine("\nThere were no domains with failed or timed out DNS queries.");
        }
    }
}