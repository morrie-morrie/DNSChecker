using CsvHelper;
using System.Globalization;

namespace DnsChecker.Helpers;

internal class ExportToCsvHelper
{
    public static void ExportResultsToCsv(string filePath, List<DomainCheckResult> results)
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
            Serilog.Log.Information($"Successfully wrote {results.Count} results to {filePath}");
        }
    }
}