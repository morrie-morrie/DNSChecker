using DNSChecker.Helpers;
using DnsChecker.Entities;
using DnsClient;
using Serilog;
using System.Net;
using System.Reflection;
using DnsChecker.Helpers;

namespace DnsChecker;

public static class Program
{
    private static async Task Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(Path.Combine("Logs", "log.txt"), rollingInterval: RollingInterval.Day)
            .CreateLogger();

        Log.Information("---------------------");
        Log.Information("Application started");

        var version = Assembly.GetExecutingAssembly().GetName().Version;
        Console.WriteLine();
        Console.WriteLine($"Application Version: {version}");

        var dnsServerAddress = IPAddress.Parse("8.8.8.8"); // Default if parsing fails
        Console.WriteLine($"The current DNS server is {dnsServerAddress}. Do you want to use a different one? (yes/no)");
        string? response = Console.ReadLine()?.Trim();

        if (response != null && response.Equals("yes", StringComparison.OrdinalIgnoreCase))
        {
            Console.Write("Enter the new DNS server IP address: ");
            string? dnsInput = Console.ReadLine()?.Trim();
            if (IPAddress.TryParse(dnsInput, out IPAddress? parsedAddress))
            {
                dnsServerAddress = parsedAddress;
                Log.Information("Using DNS server {dnsServerAddress}", dnsServerAddress);
            }
            else
            {
                Console.WriteLine("Invalid IP address. Using the current DNS server.");
            }
        }

        var clientOptions = new LookupClientOptions(dnsServerAddress)
        {
            Timeout = TimeSpan.FromSeconds(4)
        };

        var client = new LookupClient(clientOptions);

        var targetNsServers = new List<string> { "ns1.technohosting.com.au", "ns2.technohosting.com.au" };
        var targetARecords = new List<string> { "103.116.1.1", "103.116.1.2", "43.245.72.13" };

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Do you want to check an individual domain ('i'), the domain.csv file ('d'), or exit ('q')? Press Enter for 'i'.");
            var choice = Console.ReadLine()?.Trim().ToLower();

            Log.Information("User choice: {choice}", choice);

            if (string.IsNullOrEmpty(choice) || choice == "i")
            {
                Console.Write("Enter the domain to check: ");
                var domain = Console.ReadLine()?.Trim();

                if (string.IsNullOrWhiteSpace(domain))
                {
                    Console.WriteLine("No domain entered.");
                    Log.Information("No domain entered");
                    continue; // Skip to next iteration of the loop
                }

                Console.WriteLine($"Checking individual domain: {domain}");
                Log.Information("Checking individual domain: {domain}", domain);
                var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);

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
                if (result.NsRecords != null)
                {
                    foreach (var ns in result.NsRecords)
                    {
                        Console.WriteLine($"  {ns}");
                    }
                }
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine();
                Console.Write("A Match: ");
                Console.ResetColor();
                Console.ForegroundColor = result.AMatch ? ConsoleColor.Green : ConsoleColor.Red;
                Console.WriteLine(result.AMatch);
                Console.ResetColor();
                Console.WriteLine($"A Records for {result.Domain}:");

                foreach (var ip in result.ARecords ?? new List<string>())
                {
                    Console.Write($"  {ip}");

                    if (ServerNameHelper.ServerNames.ContainsKey(ip))
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write($" (running on our {ServerNameHelper.ServerNames[ip]})");
                        Console.ResetColor();
                    }
                    Console.WriteLine();
                }

                var wwwDomain = $"www.{domain}";
                Console.WriteLine($"A Records for {wwwDomain}:");
                try
                {
                    var wwwResponse = await client.QueryAsync(wwwDomain, QueryType.A);
                    var wwwARecords = wwwResponse.Answers.ARecords().Select(r => r.Address.ToString()).ToList();

                    foreach (var ip in wwwARecords)
                    {
                        Console.Write($"  {ip}");

                        if (ServerNameHelper.ServerNames.ContainsKey(ip))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.Write($" (running on our {ServerNameHelper.ServerNames[ip]})");
                            Console.ResetColor();
                        }
                        Console.WriteLine();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  Error querying A records for {wwwDomain}: {ex.Message}");
                    Log.Error(ex, $"Error querying A records for {wwwDomain}");
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

                if (result.MxRecords != null)
                {
                    foreach (var mxRecord in result.MxRecords)
                    {
                        Console.WriteLine($"  {mxRecord}");
                    }
                }
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SPF Record:");
                Console.ResetColor();

                if (!string.IsNullOrEmpty(result.SpfRecord))
                {
                    Console.Write("  Valid: ");
                    Console.ForegroundColor = result.SpfValid ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine(result.SpfValid);
                    Console.ResetColor();
                    Console.WriteLine("  Record:");
                    Console.ForegroundColor = result.SpfValid ? ConsoleColor.Green : ConsoleColor.Red;
                    Console.WriteLine($"    {result.SpfRecord}");
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
                string inputFilePath = @"c:\techno\domains.csv";  // Path to the CSV file with domains
                string outputFilePath = @"c:\techno\results.csv"; // Path to save the results

                List<string> domains = ReadDomainFromCsvHelper.ReadDomainsFromCsv(inputFilePath);
                List<DomainCheckResult> results = new List<DomainCheckResult>();

                foreach (var domain in domains)
                {
                    var result = await CheckAndMatchDomainHelper.CheckAndMatchDomain(client, domain, targetNsServers, targetARecords);
                    results.Add(result);
                }

                CheckAndMatchDomainHelper.DisplayBrokenDomains();
                Log.Information("All domains processed. Writing results to CSV");
                ExportToCsvHelper.ExportResultsToCsv(outputFilePath, results);
                Log.Information("Export completed successfully");
            }
            else if (choice == "q")
            {
                Console.WriteLine("Exiting program.");
                Log.Information("User chose to exit the program");
                break; // Exits the while loop and ends the program
            }
            else
            {
                Console.WriteLine("Invalid choice. Please enter 'i' for individual, 'd' for CSV, or 'q' to exit.");
                Log.Information("Invalid choice");
            }
        }
        Log.CloseAndFlush();
    }
}