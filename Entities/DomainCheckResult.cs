using DnsChecker.Helpers;
using System.Collections.Generic;
using System.Linq;

namespace DnsChecker.Entities;

/// <summary>
/// Represents the result of a domain DNS check, including record matches and validation results.
/// </summary>
internal class DomainCheckResult
{
    /// <summary>
    /// Gets or sets the domain name that was checked.
    /// </summary>
    public string? Domain { get; set; }
    
    /// <summary>
    /// Gets or sets a value indicating whether any of the domain's NS records match target NS servers.
    /// </summary>
    public bool NsMatch { get; set; }
    
    /// <summary>
    /// Gets or sets the list of NS records for the domain.
    /// </summary>
    public List<string>? NsRecords { get; set; }
    
    /// <summary>
    /// Gets a semicolon-separated string representation of all NS records.
    /// </summary>
    public string NsRecordsString => string.Join("; ", NsRecords ?? new List<string>());
    
    /// <summary>
    /// Gets or sets a value indicating whether any of the domain's A records match target IP addresses.
    /// </summary>
    public bool AMatch { get; set; }
    
    /// <summary>
    /// Gets or sets the list of A records (IP addresses) for the domain.
    /// </summary>
    public List<string>? ARecords { get; set; }
    
    /// <summary>
    /// Gets a semicolon-separated string representation of all A records, with server names when available.
    /// </summary>
    public string ARecordsString => string.Join("; ", ARecords?.Select(ip => GetServerName(ip)) ?? new List<string>());
    
    /// <summary>
    /// Gets or sets a value indicating whether any of the domain's MX records match target MX servers.
    /// </summary>
    public bool MxMatch { get; set; }
    
    /// <summary>
    /// Gets or sets the list of MX records for the domain.
    /// </summary>
    public List<string>? MxRecords { get; set; }
    
    /// <summary>
    /// Gets a semicolon-separated string representation of all MX records.
    /// </summary>
    public string MxRecordsString => string.Join("; ", MxRecords ?? new List<string>());
    
    /// <summary>
    /// Gets or sets a value indicating whether DNS queries for this domain failed or timed out.
    /// </summary>
    public bool IsBroken { get; set; }
    
    /// <summary>
    /// Gets or sets the reason for DNS query failure when IsBroken is true.
    /// </summary>
    public string? ErrorReason { get; set; }
    
    /// <summary>
    /// Gets or sets the SPF record for the domain.
    /// </summary>
    public string? SpfRecord { get; set; }
    
    /// <summary>
    /// Gets or sets a value indicating whether the domain's SPF record is considered valid 
    /// (ends with -all or ~all).
    /// </summary>
    public bool SpfValid { get; set; }

    /// <summary>
    /// Converts an IP address to a user-friendly string with server name if available.
    /// </summary>
    /// <param name="ip">The IP address to convert</param>
    /// <returns>String representation of the IP with server name if known</returns>
    private static string GetServerName(string ip)
    {
        if (ServerNameHelper.ServerNames.TryGetValue(ip, out string? serverName))
        {
            return $"{ip} (running on our {serverName})";
        }
        return ip;
    }
}