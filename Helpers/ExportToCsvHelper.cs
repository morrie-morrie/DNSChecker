using CsvHelper;
using DnsChecker.Entities;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace DnsChecker.Helpers;

/// <summary>
/// Helper class for exporting domain check results to CSV files.
/// </summary>
internal static class ExportToCsvHelper
{
    /// <summary>
    /// Exports a list of domain check results to a CSV file.
    /// </summary>
    /// <param name="filePath">Path where the CSV file should be saved</param>
    /// <param name="results">List of domain check results to export</param>
    /// <exception cref="ArgumentNullException">Thrown when results is null</exception>
    /// <exception cref="ArgumentException">Thrown when filePath is null or empty</exception>
    public static void ExportResultsToCsv(string filePath, List<DomainCheckResult> results)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
            
        if (results == null)
            throw new ArgumentNullException(nameof(results));

        try
        {
            // Ensure directory exists
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using (var writer = new StreamWriter(filePath))
            using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
            {
                // Write header with custom names if needed
                csv.WriteHeader<DomainExportModel>();
                csv.NextRecord();

                // Write records
                foreach (var result in results)
                {
                    var exportModel = new DomainExportModel
                    {
                        Domain = result.Domain,
                        NsMatch = result.NsMatch,
                        NsRecords = result.NsRecordsString,
                        AMatch = result.AMatch,
                        ARecords = result.ARecordsString,
                        MxMatch = result.MxMatch,
                        MxRecords = result.MxRecordsString,
                        IsBroken = result.IsBroken,
                        ErrorReason = result.ErrorReason,
                        SpfRecord = result.SpfRecord,
                        SpfValid = result.SpfValid
                    };
                    
                    csv.WriteRecord(exportModel);
                    csv.NextRecord();
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Successfully wrote {results.Count} results to {filePath}");
                Console.ResetColor();
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error exporting results to CSV at {filePath}: {ex.Message}");
            Console.ResetColor();
            throw;
        }
    }

    /// <summary>
    /// Model class used for CSV export with appropriate column names.
    /// </summary>
    private class DomainExportModel
    {
        public string? Domain { get; set; }
        public bool NsMatch { get; set; }
        public string? NsRecords { get; set; }
        public bool AMatch { get; set; }
        public string? ARecords { get; set; }
        public bool MxMatch { get; set; }
        public string? MxRecords { get; set; }
        public bool IsBroken { get; set; }
        public string? ErrorReason { get; set; }
        public string? SpfRecord { get; set; }
        public bool SpfValid { get; set; }
    }
}