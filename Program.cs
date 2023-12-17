using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using DnsClient;

class Program
{
    static async Task Main(string[] args)
    {
        // Set default DNS server to 8.8.8.8
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

        var targetNsServers = new List<string> { "ns1.technohosting.com.au", "ns2.technohosting.com.au" };
        var targetARecords = new List<string> { "103.116.1.1", "103.116.1.2" };
        var client = new LookupClient(dnsServerAddress);

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

            // Check and match NS and A records
            await CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);

            // Query and display all records
            await QueryAndDisplayAllRecords(client, domain);

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }
    }

    static async Task CheckAndMatchDomain(LookupClient client, string domain, List<string> targetNs, List<string> targetA)
    {
        var nsResponse = await client.QueryAsync(domain, QueryType.NS);
        var aResponse = await client.QueryAsync(domain, QueryType.A);
        var mxResponse = await client.QueryAsync(domain, QueryType.MX);

        var nsRecords = nsResponse.Answers.NsRecords().Select(record => record.NSDName.Value.TrimEnd('.')).ToList();
        var aRecords = aResponse.Answers.ARecords().Select(record => record.Address.ToString()).ToList();

        // Get MX records and trim the trailing dot
        var mxRecords = mxResponse.Answers.MxRecords().Select(record => record.Exchange.Value.ToLower().TrimEnd('.')).ToList();

        // Check NS records
        var nsMatch = nsRecords.Any(record => targetNs.Contains(record));
        DisplayMatchResult("NS Record", domain, nsMatch, nsRecords);

        // Check A records
        var aMatch = aRecords.Any(record => targetA.Contains(record));
        DisplayMatchResult("A Record", domain, aMatch, aRecords);

        // Check MX records for Office 365 or Proofpoint
        var isOffice365 = mxRecords.Any(record => record.EndsWith("protection.outlook.com"));
        var isProofpoint = mxRecords.Any(record => record.Contains("ppe-hosted.com") || record.Contains("proofpoint"));
        var mxMatch = isOffice365 || isProofpoint;
        DisplayMatchResult("MX Record (Office 365 or Proofpoint)", domain, mxMatch, mxRecords);
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
    static void DisplayMatchResult(string recordType, string domain, bool isMatch, List<string> records)
    {
        Console.ForegroundColor = isMatch ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine($"  {recordType} Match for {domain}: {(isMatch ? "Yes" : "No")}");
        if (!isMatch)
        {
            Console.WriteLine($"    Actual {recordType}s: {string.Join(", ", records)}");
        }
        Console.ResetColor();
    }

}
