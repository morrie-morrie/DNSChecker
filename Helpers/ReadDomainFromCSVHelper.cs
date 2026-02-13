using Serilog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace DnsChecker.Helpers;

/// <summary>
/// Helper class for reading domain names from CSV files.
/// </summary>
internal static class ReadDomainFromCsvHelper
{
    /// <summary>
    /// Reads domain names from a CSV file.
    /// </summary>
    /// <param name="filePath">Path to the CSV file containing domain names</param>
    /// <returns>A list of domain names read from the file</returns>
    /// <exception cref="ArgumentException">Thrown when filePath is null or empty</exception>
    /// <exception cref="FileNotFoundException">Thrown when the specified file doesn't exist</exception>
    public static List<string> ReadDomainsFromCsv(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));

        var domains = new List<string>();
        
        try
        {
            Console.WriteLine($"Attempting to read domains from '{filePath}'...");

            if (!File.Exists(filePath))
            {
                var message = $"File not found: {filePath}";
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(message);
                Console.ResetColor();
                throw new FileNotFoundException(message, filePath);
            }

            // Read all lines from the file
            var lines = File.ReadAllLines(filePath);

            // Process each line and add valid domains to the list
            foreach (var line in lines)
            {
                var domain = line.Trim();
                if (!string.IsNullOrWhiteSpace(domain))
                {
                    domains.Add(domain);
                }
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Successfully read {domains.Count} domains.");
            Console.ResetColor();

            // If no valid domains were found, display a warning
            if (domains.Count == 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Warning: No valid domains found in the file.");
                Console.ResetColor();
            }
        }
        catch (Exception ex) when (ex is not FileNotFoundException) // We already handle FileNotFoundException above
        {
            throw;
        }

        return domains;
    }
}