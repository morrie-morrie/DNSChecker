namespace DnsChecker.Helpers;

internal class ReadDomainFromCsvHelper
{
    public static List<string> ReadDomainsFromCsv(string filePath)
    {
        var domains = new List<string>();
        try
        {
            Console.Clear();
            Console.WriteLine($"Attempting to read domains from '{filePath}'...");

            if (File.Exists(filePath))
            {
                var lines = File.ReadAllLines(filePath);
                domains.AddRange(lines);
                Console.WriteLine($"Successfully read {lines.Length} domains.");
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine($"File not found: {filePath}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading file: {ex.Message}");
            throw;
        }

        return domains;
    }
}