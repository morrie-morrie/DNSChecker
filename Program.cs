using CsvHelper;
using DnsClient;
using Serilog;
using System.Globalization;
using System.Net;
using System.Reflection;

class DomainCheckResult
{
    public string? Domain { get; set; }
    public bool NsMatch { get; set; }
    public List<string>? NsRecords { get; set; }
    public string NsRecordsString => string.Join("; ", NsRecords ?? new List<string>());
    public bool AMatch { get; set; }
    public List<string>? ARecords { get; set; }
    public string ARecordsString => string.Join("; ", ARecords?.Select(ip => Program.ServerNames.ContainsKey(ip) ? $"{ip} (running on our {Program.ServerNames[ip]})" : ip) ?? new List<string>());
    public bool MxMatch { get; set; }
    public List<string>? MxRecords { get; set; }
    public string MxRecordsString => string.Join("; ", MxRecords ?? new List<string>());
    public bool IsBroken { get; set; }
    public string? SpfRecord { get; set; }
    public bool SpfValid { get; set; }

}



class Program
{
    static async Task Main(string[] args)
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version;
        Console.WriteLine($"Application Version: {version}");
        Console.WriteLine();

        // Set default DNS server to 8.8.8.8
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console()
            .CreateLogger();

        var dnsServerAddress = IPAddress.Parse("8.8.8.8"); // Default if parsing fails


        // Ask if the user wants to change the DNS server
        Console.WriteLine($"The current DNS server is {dnsServerAddress}. Do you want to use a different one? (yes/no)");
        var response = Console.ReadLine().Trim();

        if (response.Equals("yes", StringComparison.OrdinalIgnoreCase))
        {
            Console.Write("Enter the new DNS server IP address: ");
            var dnsInput = Console.ReadLine().Trim();
            if (IPAddress.TryParse(dnsInput, out IPAddress parsedAddress))
            {
                dnsServerAddress = parsedAddress;
            }
            else
            {
                Console.WriteLine("Invalid IP address. Using the current DNS server.");
            }
        }

        // Instantiate the LookupClient with the DNS server address
        var client = new LookupClient(dnsServerAddress) { Timeout = TimeSpan.FromSeconds(4) }; // Example: 4-second timeout


        // Target NS and A records
        var targetNsServers = new List<string> { "ns1.technohosting.com.au", "ns2.technohosting.com.au" };
        var targetARecords = new List<string> { "103.116.1.1", "103.116.1.2", "43.245.72.13" };

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Do you want to check an individual domain ('i'), the domain.csv file ('d'), or exit ('e')? Press Enter for 'i'.");
            var choice = Console.ReadLine().Trim().ToLower();

            if (string.IsNullOrEmpty(choice) || choice == "i")
            {
                Console.Write("Enter the domain to check: ");
                var domain = Console.ReadLine().Trim();

                if (string.IsNullOrWhiteSpace(domain))
                {
                    Console.WriteLine("No domain entered.");
                    continue; // Skip to next iteration of the loop
                }

                Console.WriteLine($"Checking individual domain: {domain}");
                var result = await CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);

                // Display results for the individual domain
                Console.WriteLine();
                Console.WriteLine($"Domain: {result.Domain}");

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine();
                Console.Write("NS Match: ");
                Console.ForegroundColor = result.NsMatch ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(result.NsMatch);
                Console.ResetColor();

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("NS Records:");
                Console.ResetColor();
                foreach (var ns in result.NsRecords)
                {
                    Console.WriteLine($"  {ns}");
                }

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine();
                Console.Write("A Match: ");
                Console.ResetColor();
                Console.ForegroundColor = result.AMatch ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(result.AMatch);
                Console.ResetColor();

                // Printing A Records for the root domain
                Console.WriteLine($"A Records for {result.Domain}:");
                foreach (var ip in result.ARecords ?? new List<string>())
                {
                    // Print the IP address in the original color
                    Console.Write($"  {ip}");

                    if (Program.ServerNames.ContainsKey(ip))
                    {
                        // Change color to green for specific text
                        Console.ForegroundColor = ConsoleColor.Green;

                        // Print the additional details in green
                        Console.Write($" (running on our {Program.ServerNames[ip]})");

                        // Reset the color
                        Console.ResetColor();
                    }

                    // Print the separator
                    Console.WriteLine();
                }
                // Perform an additional DNS query for the 'www' subdomain
                var wwwDomain = $"www.{domain}";
                Console.WriteLine($"A Records for {wwwDomain}:");
                try
                {
                    var wwwResponse = await client.QueryAsync(wwwDomain, QueryType.A);
                    var wwwARecords = wwwResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();

                    foreach (var ip in wwwARecords)
                    {
                        // Print the IP address in the original color
                        Console.Write($"  {ip}");

                        if (Program.ServerNames.ContainsKey(ip))
                        {
                            // Change color to green for specific text
                            Console.ForegroundColor = ConsoleColor.Green;

                            // Print the additional details in green
                            Console.Write($" (running on our {Program.ServerNames[ip]})");

                            // Reset the color
                            Console.ResetColor();
                        }

                        // Print the separator for the next record
                        Console.WriteLine();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Error querying A records for {wwwDomain}: {ex.Message}");
                }

                Console.ResetColor();

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine();
                Console.Write("MX Match: ");
                Console.ResetColor();
                Console.ForegroundColor = result.MxMatch ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(result.MxMatch);
                Console.ResetColor();

                Console.WriteLine("MX Records:");
                foreach (var mxRecord in result.MxRecords)
                {
                    Console.WriteLine($"  {mxRecord}");
                }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SPF Record:");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(result.SpfRecord))
                {
                    // Display validity status with color
                    Console.Write("  Valid: ");
                    Console.ForegroundColor = result.SpfValid ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine(result.SpfValid);

                    // Reset color before displaying "Record:" label
                    Console.ResetColor();
                    Console.WriteLine("  Record:");

                    // Apply color to the SPF record based on the "-all" check
                    Console.ForegroundColor = result.SpfValid ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine($"    {result.SpfRecord}");

                    // Reset the color back to default
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("  No SPF record found.");
                    Console.ResetColor();
                }
            }
            else if (choice == "d")
            {
                // File paths for CSV input and output
                string inputFilePath = @"c:\techno\domains.csv";  // Path to the CSV file with domains
                string outputFilePath = @"c:\techno\results.csv"; // Path to save the results

                List<string> domains = ReadDomainsFromCsv(inputFilePath);
                List<DomainCheckResult> results = new List<DomainCheckResult>();

                foreach (var domain in domains)
                {
                    var result = await CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);
                    results.Add(result);
                }

                Log.Information("All domains processed. Writing results to CSV");
                ExportResultsToCsv(outputFilePath, results);
                Log.Information("Export completed successfully");
            }
            else if (choice == "e")
            {
                Console.WriteLine("Exiting program.");
                break; // Exits the while loop and ends the program
            }
            else
            {
                Console.WriteLine("Invalid choice. Please enter 'i' for individual, 'd' for CSV, or 'e' to exit.");
            }
        }

        Log.CloseAndFlush();
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
            // Perform DNS queries
            var nsResponse = await client.QueryAsync(domain, QueryType.NS);
            var aResponse = await client.QueryAsync(domain, QueryType.A);
            var mxResponse = await client.QueryAsync(domain, QueryType.MX);
            var txtResponse = await client.QueryAsync(domain, QueryType.TXT);
            var spfParts = txtResponse.Answers.TxtRecords()
                .SelectMany(txt => txt.Text)
                .Where(txt => txt.Contains("v=spf1") || txt.Contains("include:") || txt.Contains("ip4:") || txt.Contains("ip6:") || txt.EndsWith("-all") || txt.EndsWith("~all") || txt.EndsWith("+all") || txt.EndsWith("?all"))
                .ToList();

            // Concatenate the parts of the SPF record
            result.SpfRecord = string.Join("", spfParts);

            result.SpfValid = result.SpfRecord?.EndsWith("-all") ?? false;

            // Process other DNS records
            result.NsRecords = nsResponse.Answers.NsRecords().Select(r => r.NSDName.Value.TrimEnd('.')).ToList();
            result.ARecords = aResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();
            result.MxRecords = mxResponse.Answers.MxRecords().Select(r => r.Exchange.Value.ToLower().TrimEnd('.')).ToList();

            // Perform matching checks
            result.NsMatch = result.NsRecords.Any(r => targetNs.Contains(r));
            result.AMatch = result.ARecords.Any(r => targetA.Contains(r));
            result.MxMatch = result.MxRecords.Any(r => r.EndsWith("protection.outlook.com") || r.Contains("ppe-hosted.com") || r.Contains("proofpoint"));
        }
        catch (DnsResponseException ex)
        {
            Log.Error(ex, $"DNS query failed for {domain}. Error: {ex.Message}");
            result.IsBroken = true;  // Indicate that DNS query failed for this domain
        }
        catch (Exception ex)
        {
            Log.Error(ex, $"Unexpected error occurred for {domain}");
            result.IsBroken = true;  // Indicate that there was an unexpected error
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
            csv.WriteRecords(results.Select(result => new
            {
                result.Domain,
                result.NsMatch,
                NsRecords = result.NsRecordsString,
                result.AMatch,
                ARecords = result.ARecordsString,
                result.MxMatch,
                MxRecords = result.MxRecordsString,
                result.IsBroken,
                result.SpfRecord,
                result.SpfValid
            }));
        }
    }

    public static readonly Dictionary<string, string> ServerNames = new Dictionary<string, string>
    {
        { "103.116.1.1", "CP10" },
        { "103.116.1.2", "CP11" },
        { "43.245.72.13", "CP99" }
    };

}

