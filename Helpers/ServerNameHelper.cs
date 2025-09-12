using System.Collections.Generic;

namespace DnsChecker.Helpers;

/// <summary>
/// Helper class that provides mapping between IP addresses and server names.
/// </summary>
internal static class ServerNameHelper
{
    /// <summary>
    /// Dictionary mapping IP addresses to their corresponding server names.
    /// </summary>
    public static readonly Dictionary<string, string> ServerNames = new()
    {
        { "103.116.1.1", "CP10" },
        { "103.116.1.2", "CP11" },
        { "103.116.1.4", "CP12" },
        { "43.245.72.13", "CP99" }
        // Add other server mappings here
    };

    /// <summary>
    /// Tries to get a server name for a given IP address.
    /// </summary>
    /// <param name="ipAddress">The IP address to look up</param>
    /// <param name="friendlyName">When the method returns, contains the server name associated with the IP address, if found; otherwise, null</param>
    /// <returns>True if the IP address has a server name mapping; otherwise, false</returns>
    public static bool TryGetServerName(string ipAddress, out string? friendlyName)
    {
        return ServerNames.TryGetValue(ipAddress, out friendlyName);
    }
    
    /// <summary>
    /// Gets a formatted server name string for the given IP address.
    /// </summary>
    /// <param name="ipAddress">The IP address to format with server name</param>
    /// <returns>IP address with server name in parentheses if available, or just the IP address</returns>
    public static string GetServerNameString(string ipAddress)
    {
        if (ServerNames.TryGetValue(ipAddress, out string? serverName) && serverName != null)
        {
            return $"{ipAddress} (running on our {serverName})";
        }
        return ipAddress;
    }
}