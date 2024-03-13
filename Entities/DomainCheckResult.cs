using DnsChecker.Helpers;

namespace DnsChecker.Entities;

internal class DomainCheckResult
{
    public string? Domain { get; set; }
    public bool NsMatch { get; set; }
    public List<string>? NsRecords { get; set; }
    public string NsRecordsString => string.Join("; ", NsRecords ?? new List<string>());
    public bool AMatch { get; set; }
    public List<string>? ARecords { get; set; }
    public string ARecordsString => string.Join("; ", ARecords?.Select(ip => GetServerName(ip)) ?? new List<string>());
    public bool MxMatch { get; set; }
    public List<string>? MxRecords { get; set; }
    public string MxRecordsString => string.Join("; ", MxRecords ?? new List<string>());
    public bool IsBroken { get; set; }
    public string? SpfRecord { get; set; }
    public bool SpfValid { get; set; }

    private string GetServerName(string ip)
    {
        if (ServerNameHelper.ServerNames.TryGetValue(ip, out string? serverName))
        {
            return $"{ip} (running on our {serverName})";
        }
        return ip;
    }
}