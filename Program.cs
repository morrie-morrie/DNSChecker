using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using CsvHelper;
using DnsClient;
using Serilog;

class DomainCheckResult
{
    public string Domain { get; set; }
    public bool NsMatch { get; set; }
    public List<string> NsRecords { get; set; }
    public bool AMatch { get; set; }
    public List<string> ARecords { get; set; }
    public bool MxMatch { get; set; }
    public List<string> MxRecords { get; set; }
    public bool IsBroken { get; set; }
}



class Program
{
    static async Task Main(string[] args)
    {
        const int batchSize = 100; // You can adjust this number based on your needs
                                   // Set default DNS server to 8.8.8.8
    Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .CreateLogger();

        IPAddress dnsServerAddress = IPAddress.Parse("8.8.8.8");

        // Ask if the user wants to change the DNS server
        Console.WriteLine("The default DNS server is 8.8.8.8. Do you want to use a different one? (yes/no)");
        var response = Console.ReadLine().Trim();

        if (response.Equals("yes", StringComparison.OrdinalIgnoreCase))
        {
            Console.Write("Enter the new DNS server IP address: ");
            var dnsInput = Console.ReadLine().Trim();
            if (!IPAddress.TryParse(dnsInput, out dnsServerAddress))
            {
                Console.WriteLine("Invalid IP address. Using the default DNS server (8.8.8.8).");
                dnsServerAddress = IPAddress.Parse("8.8.8.8");
            }
        }

        // Instantiate the LookupClient with the DNS server address
        var client = new LookupClient(dnsServerAddress);

        // Target NS and A records
        var targetNsServers = new List<string> { "ns1.technohosting.com.au", "ns2.technohosting.com.au" };
        var targetARecords = new List<string> { "103.116.1.1", "103.116.1.2" };

        // File paths for CSV input and output
        string inputFilePath = @"c:\techno\domains.csv";  // Path to the CSV file with domains
        string outputFilePath = @"c:\techno\results.csv"; // Path to save the results

        List<string> domains = ReadDomainsFromCsv(inputFilePath);
        List<DomainCheckResult> results = new List<DomainCheckResult>();

        int totalDomains = domains.Count;
        int processedCount = 0;

        foreach (var domain in domains)
        {
            processedCount++;
            int remaining = totalDomains - processedCount;

            Log.Information($"Processing domain {processedCount} of {totalDomains}: {domain}. Remaining: {remaining}");

            var result = await CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);
            results.Add(result);
        }

        Log.Information("All domains processed. Writing results to CSV");
        ExportResultsToCsv(outputFilePath, results);
        Log.Information("Export completed successfully");

        // Additional code for manual domain checking (optional)
        while (true)
        {
            Console.Clear();
            Console.WriteLine();
            Console.Write("Enter a domain to check (or 'exit' to quit): ");
            var domain = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(domain) || domain.Equals("exit", StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            Console.WriteLine($"Checking domain: {domain}");
            var result = await CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);

            // Optional: Display all records for the domain
            await QueryAndDisplayAllRecords(client, domain);

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            Log.CloseAndFlush();
        }
    }

    static async Task<DomainCheckResult> CheckAndMatchDomain(LookupClient client, string domain, List<string> targetNs, List<string> targetA)
    {
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
            var nsResponse = await client.QueryAsync(domain, QueryType.NS);
            var aResponse = await client.QueryAsync(domain, QueryType.A);
            var mxResponse = await client.QueryAsync(domain, QueryType.MX);

            result.NsRecords = nsResponse.Answers.NsRecords().Select(r => r.NSDName.Value.TrimEnd('.')).ToList();
            result.ARecords = aResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();
            result.MxRecords = mxResponse.Answers.MxRecords().Select(r => r.Exchange.Value.ToLower().TrimEnd('.')).ToList();

            result.NsMatch = result.NsRecords.Any(r => targetNs.Contains(r));
            result.AMatch = result.ARecords.Any(r => targetA.Contains(r));
            result.MxMatch = result.MxRecords.Any(r => r.EndsWith("protection.outlook.com") || r.Contains("ppe-hosted.com") || r.Contains("proofpoint"));
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Failed to query DNS records for {domain}");
            result.IsBroken = true;
        }

        return result;
    }



    static async Task QueryAndDisplayAllRecords(LookupClient client, string domain)
    {
        Console.WriteLine();
        Console.WriteLine($"Querying all records for {domain}:");
        var queryTypes = new List<QueryType> { QueryType.A, QueryType.AAAA, QueryType.NS, QueryType.MX, QueryType.TXT, QueryType.CNAME };
        foreach (var queryType in queryTypes)
        {
            try
            {
                var response = await client.QueryAsync(domain, queryType);
                foreach (var record in response.Answers)
                {
                    Console.WriteLine($"  {queryType} record: {record}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Error querying {queryType} records for {domain}: {ex.Message}");
            }
        }
    }
    static List<string> ReadDomainsFromCsv(string filePath)
    {
        var domains = new List<string>();
        try
        {
            Console.WriteLine($"Attempting to read domains from '{filePath}'...");

            using (var reader = new StreamReader(filePath))
            {
                string line;
                int lineCount = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    lineCount++;
                    domains.Add(line);
                }

                Console.WriteLine($"Successfully read {lineCount} domains.");
            }
        }
        catch (FileNotFoundException)
        {
            Console.WriteLine($"File not found: {filePath}");
            // Handle the exception or rethrow
            throw;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading file: {ex.Message}");
            // Handle the exception or rethrow
            throw;
        }

        return domains;
    }

    static void ExportResultsToCsv(string filePath, List<DomainCheckResult> results)
    {
        using (var writer = new StreamWriter(filePath))
        using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
        {
            csv.WriteRecords(results);
        }
    }

}