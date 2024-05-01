<#
.NOTES
Copyright (C) 2019-2024 Infoblox Inc. All rights reserved.
Version: 1.0.5.0.tags-v1.0.5.b7b95e7


PLEASE NOTE - To enable script execution on the server run:

    Set-ExecutionPolicy RemoteSigned

    Or:

    Unblock-File <this-file-name>.ps1

.SYNOPSIS

This is a script developed to collect various data about AD/DNS/DHCP infrastructure. Data collected includes basic information about AD topology,
computers, user accounts; DNS zones, records and statistics; DHCP scopes, leases and statistics.
[!!!] Please review FUNCTIONALITY section of the help to check on detailed functionality implemented by the script.

The script can be run on any Windows domain-joined machine.
[!!!] Please review DESCRIPTION section of the help to check on preprequisites that must be met before running the script.

The script do not run any create/update operation, only read ones, hence ONLY READ permissions are required for the user account that will run the script.
[!!!] Please review DESCRIPTION section of the help to check on detailed permissions that the user account must have before running the script.

.DESCRIPTION

To run this tool perform the following steps:
    1 - Log on to a Windows machine where you plan to run the script.
    2 - Ensure that all prerequisites are met to run the script.
    3 - Copy script to a writable directory where the output files are to be stored and CD to it using Powershell console.
    4 - Run the script.
    5 - Examine output for errors (in the same console window or in the log file in the ./@logs/ directory).
    6 - Logs will be created in the ./@logs/ directory, output file - in the ./@output/ directory.
    7 - Zip and send all output and log files.

PREREQUISITES:

The script is supporting Powershell 5.1 or later.

It's mandatory that you run this script on the server with several Management Tools installed.
You can check if you have them installed by running this command (run in elevated Powershell console):
    Windows Desktop systems:
    - Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools" -Online | Select-Object State
    - Get-WindowsCapability -Name "Rsat.DHCP.Tools" -Online | Select-Object State
    - Get-WindowsCapability -Name "Rsat.DNS.Tools" -Online | Select-Object State

    Windows Server systems:
    - Get-WindowsFeature -name "RSAT-AD-PowerShell"
    - Get-WindowsFeature -name "RSAT-ADDS"
    - Get-WindowsFeature -name "RSAT-ADLDS"
    - Get-WindowsFeature -name "RSAT-DHCP"
    - Get-WindowsFeature -name "RSAT-DNS"

You can install them by running this command (run in elevated Powershell console):
    Windows Desktop systems:
    - Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools" -Online
    - Add-WindowsCapability -Name "Rsat.DHCP.Tools" -Online
    - Add-WindowsCapability -Name "Rsat.DNS.Tools" -Online

    Windows Server systems:
    - Add-WindowsFeature -name "RSAT-AD-PowerShell"
    - Add-WindowsFeature -name "RSAT-ADDS"
    - Add-WindowsFeature -name "RSAT-ADLDS"
    - Add-WindowsFeature -name "RSAT-DHCP"
    - Add-WindowsFeature -name "RSAT-DNS"
--

LOCAL PERMISSIONS:

If you're running the script under a non-administrator user account on Windows machine, this account must have write permissions on the
folder where the script is located. This is required to write resulting CSV file and log files.
--

ACTIVE DIRECTORY / DHCP / DNS PERMISSIONS:

In general, the easiest way to get sufficient permissions in AD/DHCP/DNS - is to run the script under user account that has either 
'Domain Administrators' or 'Enterprise Administrators' membership (depending on the Active Directory topology). However, it's not recommended approach for the 
Active Directory.
If you're going to execute the script under limited user account, please check that it has the following permissions\membership:

    - In order to extract DHCP servers data, the user account must be a member of at least 'DHCP Users' group. This group can be either local or domain,
      depending on DHCP infrastructure. If you have multiple AD domains, user account must be added to the 'DHCP Users' group explicitly in each AD domain
      or on each DHCP server.
      More details:
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#dhcp-users
    - There are two ways to provide proper permissions to extract DNS servers data (select the one that is prefered by you):
        * User account must be a member of 'DNSAdmins' domain group (exist in each AD domain).
        * User account must have 'Read' permission on a server level in DNS MMC. This must be done in each DNS server in AD forest.

NOTE: If you decided to you administrative account to run the script, please ensure you're executing it from elevated command prompt. Otherwise, you may
      receive errors while running operations against DHCP and/or DNS services.

--

.FUNCTIONALITY

The script will collect 27 metrics. Each metric is collected separately by a single Powershell function.
These functions are included in this script file right after 'param()' keyword. Functions have the following name format: 'infoblox_<metric-name>'.
Each function in its turn has help section that describes the logic.

List of metrics:
    - dhcp_device_count
    - dhcp_lease_time
    - dhcp_lps
    - dhcp_server_count
    - dhcp_subnet_count
    - dhcp_vendor
    - dns_ext_dnssec_used
    - dns_ext_forward_zone_count
    - dns_ext_ipv6_used
    - dns_ext_qps
    - dns_ext_record_count
    - dns_ext_reverse_zone_count
    - dns_ext_server_count
    - dns_int_ad_domain_count
    - dns_int_caching_forwarders
    - dns_int_dnssec_used
    - dns_int_forward_zone_count
    - dns_int_ipv6_used
    - dns_int_qps
    - dns_int_record_count
    - dns_int_reverse_zone_count
    - dns_int_server_count
    - dns_int_vendor
    - gen_active_ip
    - gen_active_user
    - gen_site_count
    - gen_vendor

#>


[CmdletBinding()]
param ();


#region ./_templates/common--main--header.ps1
#endregion /./_templates/common--main--header.ps1


#region ./_helpers/public/
#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpScope.ps1
function Get-IbAdDhcpScope {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        # DHCP server FQDN
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$dhcpServer,
        
        # Get only 'ipv4' scopes
        [Parameter(ParameterSetName = "ipv4")][switch]$ipv4,

        # Get only 'ipv6' scopes
        [Parameter(ParameterSetName = "ipv6")][switch]$ipv6
    );

    
    BEGIN {
        "Running 'Get-IbAdDhcpScope'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;
        $ipv4Scopes = $null;
        $ipv6Scopes = $null;


        #region Get all scopes
        try
        {
            "Getting scopes from the DHCP server '$dhcpServer'." | Write-IbLogfile | Write-Verbose;
            [array]$ipv4Scopes = Get-DhcpServerv4Scope -ComputerName $dhcpServer -ErrorAction Stop;
            [array]$ipv6Scopes = Get-DhcpServerv6Scope -ComputerName $dhcpServer -ErrorAction Stop;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get scopes from DHCP server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get all scopes


        if ($ipv4)
        {
            "'ipv4' flag passed. Returning IPv4 scopes only." | Write-IbLogfile | Write-Verbose;
            [System.Collections.ArrayList]$result = $ipv4Scopes;
        }
        elseif ($ipv6)
        {
            "'ipv6' flag passed. Returning IPv6 scopes only." | Write-IbLogfile | Write-Verbose;
            [System.Collections.ArrayList]$result = $ipv6Scopes;
        }
        else
        {
            [System.Collections.ArrayList]$result = $ipv4Scopes + $ipv6Scopes;
        }


        if ($result)
        {
            $result | %{ $_ | Add-Member -MemberType NoteProperty -Name "DhcpServer" -Value $dhcpServer };
        }
        else
        {
            $result = @();
        }

        
        "$($result.Count) scopes found." | Write-IbLogfile | Write-Verbose;
        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpScope'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpScope.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServer.ps1
function Get-IbAdDhcpServer {
    [CmdletBinding()]
    param (
        # Do not verify if DHCP is running
        [Parameter()][switch]$doNotTestService
    );

    
    BEGIN {
        "Running 'Get-IbAdDhcpServer'." | Write-IbLogfile | Write-Verbose;

        $result = $null;
    }

    
    PROCESS {
        "Getting list of authorized DHCP servers from AD." | Write-IbLogfile | Write-Verbose;


        #region Getting DHCP servers using Powershell
        try
        {
            [array]$result = Get-DhcpServerInDC -ErrorAction Stop | Select-Object -ExpandProperty DnsName;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get the list of DHCP servers from AD using Powershell module.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Getting DHCP servers using Powershell


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServerLps.ps1
function Get-IbAdDhcpServerLps {
    [CmdletBinding()]
    param (
        # DHCP server
        [Parameter(ValueFromPipeline)][string]$dhcpServer
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDhcpServerLps'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting information from '$dhcpServer' DHCP server." | Write-IbLogfile | Write-Verbose;

        #region Getting DHCP server statistics
            #region Getting IPv4 statistics
            try
            {
                "Getting DHCP server IPv4 statistics." | Write-IbLogfile | Write-Verbose;
                $ipv4Stats = Get-DhcpServerv4Statistics -ComputerName $dhcpServer -ErrorAction Stop;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get DHCP server IPv4 statistics from the server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            #endregion /Getting IPv4 statistics


            #region Getting IPv6 statistics
            try
            {
                "Getting DHCP server IPv6 statistics." | Write-IbLogfile | Write-Verbose;
                $ipv6Stats = Get-DhcpServerv6Statistics -ComputerName $dhcpServer -ErrorAction Stop;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get DHCP server IPv6 statistics from the server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            #endregion /Getting IPv6 statistics
            #endregion /Getting DHCP server statistics

            $uptime = ($(Get-Date) - $ipv4Stats.ServerStartTime).TotalSeconds;
            [float]$ipv4Lps = [Math]::Round($ipv4Stats.Acks / $uptime, 2);
            [float]$ipv6Lps = [Math]::Round($ipv6Stats.Confirms / $uptime, 2);

            return $($ipv4Lps + $ipv6Lps);
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServerLps'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServerLps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_device_count.ps1
function infoblox_dhcp_device_count {
    <#
    .DESCRIPTION
        The script will return number of leases in all scopes (IPv4 and IPv6) in all DHCP servers in AD forest.
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_device_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        [array]$dhcpServers = Get-IbAdDhcpServer;


        [array]$ipv4Devices = $dhcpServers | Get-IbAdDhcpScope -ipv4 | ?{$_.State -eq "Active"} | %{
            Get-DhcpServerv4Lease -ComputerName $_.DhcpServer -scopeid $_.ScopeId;
        }
        [array]$ipv6Devices = $dhcpServers | Get-IbAdDhcpScope -ipv6 | ?{$_.State -eq "Active"} | %{
            Get-DhcpServerv6Lease -ComputerName $_.DhcpServer -Prefix $_.Prefix;
        }

        [array]$result = $ipv4Devices + $ipv6Devices;
        return @("dhcp_device_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dhcp_device_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_device_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_lease_time.ps1
function infoblox_dhcp_lease_time {
    <#
    .DESCRIPTION
        This functions will return average value (in seconds) for lease duration option for all scopes in all DHCP servers in AD forest.
        
        For IPv4 scopes 'Lease Duration' value is taken.
        For IPv6 scopes 'Preferred Lifetime' value is taken.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_lease_time'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        [array]$dhcpServers = Get-IbAdDhcpServer;

        $ipv4Average = $dhcpServers `
            | Get-IbAdDhcpScope -ipv4 `
            | ?{$_.State -eq "Active"} `
            | Select-Object @{name = "leaseTime"; expression = {$_.LeaseDuration.TotalSeconds}} `
            | Select-Object -ExpandProperty leaseTime `
            | Measure-Object -Average `
            | Select-Object -ExpandProperty Average;

        $ipv6Average = $dhcpServers `
            | Get-IbAdDhcpScope -ipv6 `
            | ?{$_.State -eq "Active"} `
            | Select-Object @{name = "leaseTime"; expression = {$_.PreferredLifetime.TotalSeconds}} `
            | Select-Object -ExpandProperty leaseTime `
            | Measure-Object -Average `
            | Select-Object -ExpandProperty Average;

        [float]$result = ($ipv4Average + $ipv6Average) / 2;

        return @("dhcp_lease_time", $result);
    }
    
    END {
        "[***] Finished collection 'dhcp_lease_time'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_lease_time.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_lps.ps1
function infoblox_dhcp_lps {
    <#
    .DESCRIPTION
        The function will return LPS (leases per second) for all authorized DHCP servers in AD forest.
        LPS counts per IPv4 and IPv6 zones independently and later summarized.

        LPS calculation formulas:
            - IPv4: 'Ack' responses / server uptime
            - IPv6: 'Confirm' responses / server uptime
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_lps'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        [float]$result = Get-IbAdDhcpServer | Get-IbAdDhcpServerLps | Measure-Object -Average | Select-Object -ExpandProperty Average;
        [float]$result = [Math]::Round($result, 2);

        return @("dhcp_lps", $result);
    }

    END {
        "[***] Finished collection 'dhcp_lps'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_lps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_server_count.ps1
function infoblox_dhcp_server_count {
    <#
    .DESCRIPTION
        The function will return number of all authorized DHCP servers in AD forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_server_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        [array]$result = Get-IbAdDhcpServer;

        return @("dhcp_server_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dhcp_server_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_subnet_count.ps1
function infoblox_dhcp_subnet_count {
    <#
    .DESCRIPTION
        The function return number of all active scopes (IPv4 and IPv6) from all DHCP servers in AD forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_subnet_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        [array]$result = Get-IbAdDhcpServer | Get-IbAdDhcpScope | ?{$_.State -eq "Active"};

        return @("dhcp_subnet_count", $result.Count);
    }
    
    END {
        "[***] Finished collection 'dhcp_subnet_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_subnet_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_vendor.ps1
function infoblox_dhcp_vendor {
    <#
    .DESCRIPTION
        The function will return AD Forest functional level.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_vendor'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $result = Get-ADForest | Select-Object -ExpandProperty ForestMode;
        return @("gen_vendor", $result);
    }

    END {
        "[***] Finished collection 'dhcp_vendor'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_dnssec_used.ps1
function infoblox_dns_ext_dnssec_used {
    <#
    .DESCRIPTION
        The function will return 0 or 1, depending on the the usage of DNSSEC.

        1 - if (at least one DNSSEC record exist in any 'external' DNS server in AD forest)
        0 - otherwise
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_dnssec_used'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$dnssecRecords = $domains | Get-IbAdDnsServer | Select-Object -Unique | Get-IbAdDnsZone -forward -external | Get-IbAdDnsDnssecRecord;

        if ($dnssecRecords) { $result = 1 } else { $result = 0 };
        return @("dns_ext_dnssec_used", $result);
    }
    
    END {
        "[***] Finished collection 'dns_ext_dnssec_used'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_dnssec_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_forward_zone_count.ps1
function infoblox_dns_ext_forward_zone_count {
    <#
    .DESCRIPTION
        The function will return number of all 'external' forward DNS zones from all DNS servers in the AD forest.
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        $dnsServers = $domains | Get-IbAdDnsServer | Select-Object -Unique;

        [array]$result = $dnsServers | Get-IbAdDnsZone -forward -external | Sort-Object -Unique -Property ZoneName;
        return @("dns_ext_forward_zone_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_ext_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_forward_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_ipv6_used.ps1
function infoblox_dns_ext_ipv6_used {
    <#
    .DESCRIPTION
        The function will return 0 or 1, depending on the usage of IPv6 protocol.

        1 - if (there are AAAA records in the 'external' DNS zones in all DNS servers in AD forest (conditions apply here based on IPv4/IPv6 ratio))
            OR
            if (there are IPv6 AD replication subnets exist)
        0 - otherwise
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_ipv6_used'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$ipv6Zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -external | Get-IbAdDnsZone -external -ipv6;
        [array]$ipv6Subnets = Get-IbAdSubnet -ipv6;

        if ($ipv6Zones -or $ipv6Subnets) { $result = 1 } else { $result = 0 };
        return @("dns_ext_ipv6_used", $result);
    }
    
    END {
        "[***] Finished collection 'dns_ext_ipv6_used'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_ipv6_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_qps.ps1
function infoblox_dns_ext_qps {
    <#
    .DESCRIPTION
        The function will detect all 'external' DNS servers in AD forest, get DNS Server statistics, and from it - TotalQueries and CurrentUptime metrics.
        Total queries number divided by uptime secods will give QPS metric for all DNS servers (internal).
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_qps'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        [float]$result = $domains `
            | Get-IbAdDnsServer | Select-Object -Unique `
            | Select-IbAdDnsServer -external `
            | Get-IbAdDnsZone -external | Select-Object -Unique DnsServer -ExpandProperty DnsServer `
            | Get-IbAdDnsServerQps `
            | Measure-Object -Sum | Select-Object -ExpandProperty Sum;
            
        [float]$result = [Math]::Round($result, 2);

        return @("dns_ext_qps", $result);
    }
    
    END {
        "[***] Finished collection 'dns_ext_qps'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_qps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_record_count.ps1
function infoblox_dns_ext_record_count {
    <#
    .DESCRIPTION
        The function will return number of all DNS records from all 'external' DNS zones from all DNS servers in the AD forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_record_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $result = @();
        $domains = (Get-ADForest).Domains;
        [array]$zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -external | Get-IbAdDnsZone -external | Sort-Object -Unique -Property ZoneName;

        foreach ($zone in $zones)
        {
            $result += Get-DnsServerResourceRecord -ComputerName $zone.DnsServer -ZoneName $zone.ZoneName;
        }

        return @("dns_ext_record_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_ext_record_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_record_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_reverse_zone_count.ps1
function infoblox_dns_ext_reverse_zone_count {
    <#
    .DESCRIPTION
        The function will return number of all 'external' reverse DNS zones from all DNS servers in the forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        $dnsServers = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -external;

        [array]$result = $dnsServers | Get-IbAdDnsZone -external -reverse | Sort-Object -Unique -Property ZoneName;
        return @("dns_ext_reverse_zone_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_ext_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_reverse_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_server_count.ps1
function infoblox_dns_ext_server_count {
    <#
    .DESCRIPTION
        The function will return number of all DNS servers, that have 'external' DNS zones, in the forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_server_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$result = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -external;

        return @("dns_ext_server_count", $result.count);
    }

    END {
        "[***] Finished collection 'dns_ext_server_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_ext_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_ad_domain_count.ps1
function infoblox_dns_int_ad_domain_count {
    <#
    .DESCRIPTION
        The function will return number AD domains in the forest.
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_ad_domain_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        [array]$result = (Get-ADForest).Domains;

        return @("dns_int_ad_domain_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_int_ad_domain_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_ad_domain_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_caching_forwarders.ps1
function infoblox_dns_int_caching_forwarders {
    <#
    .DESCRIPTION
        The function will return number of all DNS servers in AD forest with explicit or conditional forwarding configured.
    #>
    
    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_caching_forwarders'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$result = $domains | Get-IbAdDnsServer | Select-Object -Unique | Get-IbAdDnsForwarderConfiguration | ?{$_.general -or $_.conditional};

        return @("dns_int_caching_forwarders", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_int_caching_forwarders'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_caching_forwarders.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_dnssec_used.ps1
function infoblox_dns_int_dnssec_used {
    <#
    .DESCRIPTION
        The function will return 0 or 1, depending on the the usage of DNSSEC.

        1 - if (at least one DNSSEC record exist in any 'internal' DNS server in AD forest)
        0 - otherwise
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_dnssec_used'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$dnssecRecords = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -forward -internal | Get-IbAdDnsDnssecRecord;

        if ($dnssecRecords) { $result = 1 } else { $result = 0 };
        return @("dns_int_dnssec_used", $result);
    }

    END {
        "[***] Finished collection 'dns_int_dnssec_used'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_dnssec_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_forward_zone_count.ps1
function infoblox_dns_int_forward_zone_count {
    <#
    .DESCRIPTION
        The function will return number of all 'internal' forward DNS zones from all DNS servers in the AD forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$result = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -forward -internal | Sort-Object -Unique -Property ZoneName;
        
        return @("dns_int_forward_zone_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_int_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_forward_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_ipv6_used.ps1
function infoblox_dns_int_ipv6_used {
    <#
    .DESCRIPTION
        The function will return 0 or 1, depending on the usage of IPv6 protocol.

        1 - if (there are AAAA records in the 'internal' DNS zones in all DNS servers in AD forest (conditions apply here based on IPv4/IPv6 ratio))
            OR
            if (there are IPv6 AD replication subnets exist)
        0 - otherwise
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_ipv6_used'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$ipv6Zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -internal -ipv6;
        [array]$ipv6Subnets = Get-IbAdSubnet -ipv6;

        if ($ipv6Zones -or $ipv6Subnets) { $result = 1 } else { $result = 0 };
        return @("dns_int_ipv6_used", $result);
    }

    END {
        "[***] Finished collection 'dns_int_ipv6_used'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_ipv6_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_qps.ps1
function infoblox_dns_int_qps {
    <#
    .DESCRIPTION
        The function will detect all 'internal' DNS servers in AD forest, get DNS Server statistics, and from it - TotalQueries and CurrentUptime metrics.
        Total queries number divided by uptime secods will give QPS metric for all DNS servers (internal).
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_qps'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;
        [float]$result = $domains `
            | Get-IbAdDnsServer | Select-Object -Unique `
            | Select-IbAdDnsServer -internal `
            | Get-IbAdDnsZone -internal | Select-Object -Unique DnsServer -ExpandProperty DnsServer `
            | Get-IbAdDnsServerQps `
            | Measure-Object -Sum | Select-Object -ExpandProperty Sum;
            
        [float]$result = [Math]::Round($result, 2);

        return @("dns_int_qps", $result);
    }

    END {
        "[***] Finished collection 'dns_int_qps'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_qps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_record_count.ps1
function infoblox_dns_int_record_count {
    [CmdletBinding()]
    <#
    .DESCRIPTION
        The function will return number of all DNS records from all 'internal' DNS zones from all DNS servers in the AD forest.
    #>
    
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_record_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $result = @();
        $domains = (Get-ADForest).Domains;
        [array]$zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -internal | Sort-Object -Unique -Property ZoneName;

        foreach ($zone in $zones)
        {
            $result += Get-DnsServerResourceRecord -ComputerName $zone.DnsServer -ZoneName $zone.ZoneName;
        }
        
        return @("dns_int_record_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_int_record_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_record_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_reverse_zone_count.ps1
function infoblox_dns_int_reverse_zone_count {
    <#
    .DESCRIPTION
        The function will return number of all 'internal' reverse DNS zones from all DNS servers in the forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$result = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -reverse -internal | Sort-Object -Unique -Property ZoneName;

        return @("dns_int_reverse_zone_count", $result.Count);
    }
    
    END {
        "[***] Finished collection 'dns_int_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_reverse_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_server_count.ps1
function infoblox_dns_int_server_count {
    <#
    .DESCRIPTION
        The function will return number of all DNS servers, that does not have 'external' DNS zones (i.e., has 'internal' only), in the forest.
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_server_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $result = @();

        $domains = (Get-ADForest).Domains;
        [array]$result = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal;
        
        return @("dns_int_server_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'dns_int_server_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_vendor.ps1
function infoblox_dns_int_vendor {
    <#
    .DESCRIPTION
        The function will return AD Forest functional level.
    #>
    
    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_vendor'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $result = Get-ADForest | Select-Object -ExpandProperty ForestMode;
        return @("dns_int_vendor", $result);
    }
    
    END {
        "[***] Finished collection 'dns_int_vendor'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dns_int_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_active_ip.ps1
function infoblox_gen_active_ip {
    <#
    .DESCRIPTION
        The function will return number of servers, computers and domain controllers from all AD domains in the forest.
    #>

    [CmdletBinding()]
    param ();
    
    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'infoblox_gen_active_ip'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $domains = (Get-ADForest).Domains;

        [array]$adServers = $domains | %{ Get-IbAdServer -domain $_ };
        [array]$adControllers = $domains | %{ Get-IbAdDomainController -domain $_ };
        [array]$adWorkstations = $domains | %{ Get-IbAdWorkstation -domain $_ };

        [int]$result = $adServers.Count + $adControllers.Count + $adWorkstations.Count;
        return @("gen_active_ip", $result);
    }
    
    END {
        "[***] Finished collection 'infoblox_gen_active_ip'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_active_ip.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_active_user.ps1
function infoblox_gen_active_user {
    <#
    .DESCRIPTION
        The function will return all user accounts from all AD domains in the forest.
        Disabled and ServiceAccounts (like *SvcAccount) will be filtered out.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'infoblox_gen_active_user'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        $domains = (Get-ADForest).Domains;
        [array]$users = $domains | Get-IbAdUser -enabledOnly -excludeServiceAccounts;
        return @("gen_active_user", $users.Count);
    }

    END {
        "[***] Finished collection 'infoblox_gen_active_user'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_active_user.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_site_count.ps1
function infoblox_gen_site_count {
    <#
    .DESCRIPTION
        The function will return number of AD replication sites in the forest.
    #>

    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_site_count'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $result = (Get-ADForest).Sites;

        return @("gen_site_count", $result.count);
    }
    
    END {
        "[***] Finished collection 'gen_site_count'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_site_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_vendor.ps1
function infoblox_gen_vendor {
    <#
    .DESCRIPTION
        The function will return AD Forest functional level.
    #>
    
    [CmdletBinding()]
    param ();

    BEGIN {
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_vendor'." | Write-IbLogfile | Write-Verbose;
    }
    
    PROCESS {
        $result = Get-ADForest | Select-Object -ExpandProperty ForestMode;
        return @("gen_vendor", $result);
    }
    
    END {
        "[***] Finished collection 'gen_vendor'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Export-IbCsv.ps1
function Export-IbCsv {
    [CmdletBinding()]
    param (
        # Array of arrays to export
        [Parameter(Mandatory, ValueFromPipeline)][array[]]$array,

        # CSV separator
        [Parameter()][string]$separator = ","
    );
    
    
    BEGIN {
        $csvPath = $env:INFOBLOX_SE_CSVPATH;
    }

    
    PROCESS {
        foreach ($item in $array) {
            $csvString = "";
            foreach ($subItem in $item) {
                $csvString += "$subItem$separator";
            }
            $csvString = $csvString.TrimEnd($separator);

            Add-Content -Path $csvPath -Value $csvString;
        }
    }
    

    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Export-IbCsv.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Set-IbCsvfilePath.ps1
function Set-IbCsvfilePath {
    [CmdletBinding()]
    param (
        # Csv file name
        [Parameter()][string]$fileName
    );

    
    $csvPath = "./@output/";


    #region Create path to the log file if it doesn't exist
    if (-not $(Test-Path -Path "$csvPath/$fileName")) {
        New-Item -Path "$csvPath/$fileName" -Force;
    }
    #endregion /Create path to the log file if it doesn't exist


    Write-Verbose "Setting environment variable 'INFOBLOX_SE_CSVPATH = $csvPath/$fileName' to store CSV file path.";
    Set-Item -Path "env:INFOBLOX_SE_CSVPATH" -Value "$csvPath/$fileName";
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Set-IbCsvfilePath.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Set-IbLogfilePath.ps1
function Set-IbLogfilePath {
    [CmdletBinding()]
    param (
        [Parameter()][string]$fileName,

        [Parameter()][switch]$powershellTranscript
    );


    $logPath = "./@logs/"

    if (-not $fileName) {
        $fileName = "{0}.log" -f $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss");
    }


    if (-not $powershellTranscript)
    {
        #region Create path to the log file if it doesn't exist
        if (-not $(Test-Path -Path "$logPath/$fileName")) {
            New-Item -Path "$logPath/$fileName" -Force;
        }
        #endregion /Create path to the log file if it doesn't exist
    
        Write-Verbose "Setting environment variable 'INFOBLOX_SE_LOGPATH = $logPath/$fileName' to store log file path.";
        Set-Item -Path "env:INFOBLOX_SE_LOGPATH" -Value "$logPath/$fileName";
    
        Write-Verbose "Writing init record into log file.";
        Write-IbLogfile "Log file initialized." -noOutput;
    }
    else
    {
        Write-Verbose "Setting environment variable 'INFOBLOX_PWSH_TRANSCRIPT_PATH = $logPath/$fileName' to store Powershell transcript path.";
        Set-Item -Path "env:INFOBLOX_PWSH_TRANSCRIPT_PATH" -Value "$logPath/$fileName";
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Set-IbLogfilePath.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Write-IbLogfile.ps1
function Write-IbLogfile {
    [CmdletBinding()]
    param (
        # Message passed to the log
        [Parameter(Mandatory, ValueFromPipeline)][ValidateNotNullorEmpty()]
        [string]
        $text,

        # Message severity passed to the log
        [Parameter()][ValidateNotNullorEmpty()][ValidateSet("Info", "Error", "Warning")]
        [string]
        $severity = "Info",

        # Do not return $text as output
        [Parameter()][switch]$noOutput
    );


    BEGIN {
        $logPath = $env:INFOBLOX_SE_LOGPATH;
    }
 

    PROCESS {
        $datetimeStamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss->fff";
        
        #region Format spaces
        if ($severity.Length -le 7) {
            $severityStamp = "[$severity]";
            for ($i = $severity.Length; $i -le 7; $i++) {
                $severityStamp = $severityStamp + " ";
            }
        }
        #endregion /Format spaces


        try {
            Add-Content -Path $logPath -Encoding UTF8 -Value $($datetimeStamp + "  $severityStamp " + $text) -ErrorAction Stop;
        }
        catch {
            Write-Error "Error while trying to write the log file '$logPath'.";
            throw $_;
        }


        if (-not $noOutput) { return $text; }
    }
 

    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Write-IbLogfile.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdDomainController.ps1
function Get-IbAdDomainController {
    [CmdletBinding()]
    param (
        # Domain name
        [Parameter()][string]$domainName,

        # Filter by Global Catalog role
        [Parameter()][switch]$globalCatalog
    );

    
    BEGIN {
        $result = -2;
        "Running 'Get-IbAdDomainController'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $params = @{};

        #region Processing 'domainName' parameter flag was passed
        if ($domainName)
        {
            "Discovering AD domain controllers for the '$domainName' AD domain." | Write-IbLogfile | Write-Verbose;
            $params.Server = $domainName;
        }
        else
        {
            "Discovering AD domain controllers for the current AD domain." | Write-IbLogfile | Write-Verbose;
            $params = @{};
        }
        #endregion /Processing 'domainName' parameter flag was passed


        #region 'globalCatalog' flag was passed
        if ($globalCatalog) {
            "'globalCatalog' flag was passed." | Write-IbLogfile | Write-Verbose;
            $params.Service = "GlobalCatalog";
        }
        #endregion /'globalCatalog' flag was passed


        #region Sending request
        try
        {
            [array]$result = Get-ADDomainController @params -Filter "*" -ErrorAction Stop;
            "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_common";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to discover AD domain controller for '$domain' domain.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Sending request


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDomainController'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdDomainController.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdServer.ps1
function Get-IbAdServer {
    [CmdletBinding()]
    param (
        # Computer name. You can use wildcard characters here.
        # Documentation: https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax#wildcards
        [Parameter()][string]$name,
    
        # Properties to load from AD. Send empty array for all properties.
        [Parameter()][string[]]$properties = @("name"),

        # AD domain name (FQDN)
        [Parameter()][ValidateNotNullOrEmpty()][string]$domain,

        # User ADSI queries instead of Powershell
        [Parameter()][switch]$useAdsi
    );

    
    BEGIN {
        $result = -2;
        "Running 'Get-IbAdServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        if ($useAdsi)
        {
            #region Using ADSI queries
            "'useAdsi' flag was passed. Will be using ADSI queries instead of Powershell." | Write-IbLogfile | Write-Verbose;


            #region Setting ADSI filter
            if ($name)
            {
                "Getting server '$name' from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $query = "(&(&(objectCategory=computer)(objectClass=computer)(name=$name)(operatingSystem=*server*)))";
            }
            else
            {
                "Getting servers from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $query = "(&(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*)))";
            }
            #endregion /Setting ADSI filter


            if ($domain) { $searchRoot = [adsi]"LDAP://$domain/dc=$($domain.Split(".") -join ",dc=")"; }


            [array]$result = Invoke-IbAdAdsiQuery -query $query -searchRoot $searchRoot -properties $properties;
            #endregion /Using ADSI queries
        }
        else
        {
            #region Using Powershell cmdlets
            $params = @{};


            #region Setting ADSI filter
            if ($name)
            {
                "Getting server '$name' from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;

                $ldapFilter = "(name=$name)(operatingSystem=*server*)";
            }
            else
            {
                "Getting servers from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;

                $ldapFilter = "(operatingSystem=*server*)";
            }
            #endregion /Setting ADSI filter
            


            if ($domain) { $params.Server = $domain; }


            try
            {
                [array]$result = Get-ADComputer @params -LDAPFilter $ldapFilter -Properties $properties -ErrorAction Stop;
                "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_common";
                    message = $_;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get computer objects from AD for '$domain' domain.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            #endregion /Using Powershell cmdlets
        }
        

        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdSubnet.ps1
function Get-IbAdSubnet {
    [CmdletBinding(DefaultParameterSetName = "ipv4")]
    param (
        # Return IPv6 subnets only
        [Parameter(ParameterSetName = "ipv6")]
        [switch]
        $ipv6,

        # Return IPv4 subnets only
        [Parameter(ParameterSetName = "ipv4")]
        [switch]
        $ipv4
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdSubnet'." | Write-IbLogfile | Write-Verbose;

        $privateIpv4Ranges = "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)";
        $privateIpv6Ranges = "^f[cd][0-9a-fA-F]{2}:"; # fc00::/7
        $localIpv6Ranges = "^fe[89abAB][0-9a-fA-F]:"; # fe80::/10
    }

    
    PROCESS {
        "Getting AD replication subnets." | Write-IbLogfile | Write-Verbose;

        try
        {
            [array]$result = Get-ADReplicationSubnet -Filter "*" -ErrorAction Stop;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_common";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get AD replication subnets.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }


        if ($ipv4)
        {
            "'ipv4' flag passed. Returning IPv4 subnets only." | Write-IbLogfile | Write-Verbose;
            [array]$result = $result | ?{$_.name -match $privateIpv4Ranges};
        }


        if ($ipv6)
        {
            "'ipv6' flag passed. Returning IPv6 subnets only." | Write-IbLogfile | Write-Verbose;
            [array]$result = $result | ?{$_.name -match $privateIpv6Ranges -or $_.name -match $localIpv6Ranges};
        }


        "$($result.count) subnets found." | Write-IbLogfile | Write-Verbose;


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdSubnet'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdSubnet.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdUser.ps1
function Get-IbAdUser {
    [CmdletBinding(DefaultParameterSetName = "EnabledAndDisabled")]
    param (
        # Properties to load from AD. Send empty array for all properties.
        [Parameter()][string[]]$properties = @("name"),

        # Search for disabled users only
        [Parameter(ParameterSetName = "DisabledOnly")][switch]$disabledOnly,

        # Search for enabled users only
        [Parameter(ParameterSetName = "EnabledOnly")][switch]$enabledOnly,

        # Exclude accounts with names finishing with 'SvcAccount'
        [Parameter()][switch]$excludeServiceAccounts,

        # DC to connect to
        [Parameter(ValueFromPipeline)][string]$server
    );

    
    BEGIN {
        $result = -2;
        "Running 'Get-IbAdUser'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $params = [hashtable]@{
            filter = @();
        };


        #region Processing 'excludeServiceAccounts' parameter
        if ($excludeServiceAccounts)
        {
            $params.filter += "Name -notlike '*SvcAccount'";
        }
        #endregion /Processing 'excludeServiceAccounts' parameter


        #region Processing 'disabledOnly' flag
        if ($disabledOnly)
        {
            "'disabledOnly' flag was passed. Setting additional ADSI filter." | Write-IbLogfile | Write-Verbose;
            $params.filter += "Enabled -eq 'False'";
        }
        #endregion /Processing 'disabledOnly' flag


        #region Processing 'enabledOnly' flag
        if ($enabledOnly)
        {
            "'enabledOnly' flag was passed. Setting additional ADSI filter." | Write-IbLogfile | Write-Verbose;
            $params.filter += "Enabled -eq 'True'";
        }
        #endregion /Processing 'enabledOnly' flag


        #region Process 'server'
        if ($server)
        {
            "'server' parameter specified. Using '$server' as a source for users." | Write-IbLogfile | Write-Verbose;
            $params.server = $server;
        }
        #endregion Process 'server'


        try
        {
            if ($params.filter.count -eq 0)
            {
                $params.filter = "*";
            }
            else
            {
                $params.filter = $($params.filter | ?{$_ -ne "*"}) -join " -and ";
            }
            "Using filter: '$($params.filter)'." | Write-IbLogfile | Write-Verbose;
            [array]$result = Get-ADUser @params -Properties $properties -ErrorAction Stop;

            "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_common";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while getting users from AD ('$server' domain controller).`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdUser'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdUser.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdWorkstation.ps1
function Get-IbAdWorkstation {
    [CmdletBinding()]
    param (
        # Computer name. You can use wildcard characters here.
        # Documentation: https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax#wildcards
        [Parameter()]
        [string]
        $name,
    
        # Properties to load from AD. Send empty array for all properties.
        [Parameter()]
        [string[]]
        $properties = @("name"),

        # AD domain name (FQDN)
        [Parameter()][ValidateNotNullOrEmpty()][string]$domain,

        # User ADSI queries instead of Powershell
        [Parameter()]
        [switch]
        $useAdsi
    );

    
    BEGIN {
        $result = -2;
        "Running 'Get-IbAdWorkstation'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        if ($useAdsi)
        {
            #region Using ADSI queries
            "'useAdsi' flag was passed. Will be using ADSI queries instead of Powershell." | Write-IbLogfile | Write-Verbose;

            #region Setting ADSI filter
            if ($name)
            {
                "Getting workstation '$name' from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $query = "(&(&(objectCategory=computer)(objectClass=computer)(name=$name)(!operatingSystem=*server*)))";
            }
            else
            {
                "Getting workstations from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $query = "(&(&(objectCategory=computer)(objectClass=computer)(!operatingSystem=*server*)))";
            }
            #endregion /Setting ADSI filter


            if ($domain)
            {
                $searchRoot = [adsi]"LDAP://$domain/dc=$($domain.Split(".") -join ",dc=")";
            }


            [array]$result = Invoke-IbAdAdsiQuery -query $query -searchRoot $searchRoot -properties $properties;
            #endregion /Using ADSI queries
        }
        else
        {
            #region Using Powershell cmdlets
            $params = @{};


            #region Setting ADSI filter
            if ($name)
            {
                "Getting workstation '$name' from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $ldapFilter = "(name=$name)(!operatingSystem=*server*)";
            }
            else
            {
                "Getting workstations from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
                $ldapFilter = "(!operatingSystem=*server*)";
            }
            #endregion /Setting ADSI filter


            if ($domain) { $params.Server = $domain; }
            

            try
            {
                [array]$result = Get-ADComputer @params -LDAPFilter $ldapFilter -Properties $properties -ErrorAction Stop;
                "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_common";
                    message = $_;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get computer objects from AD for '$domain' domain.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            #endregion /Using Powershell cmdlets
        }


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdWorkstation'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdWorkstation.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsDnssecRecord.ps1
function Get-IbAdDnsDnssecRecord {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$dnsServer,

        # DNS server forward zone
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$zoneName
    );

    
    BEGIN {
        $result = $null;
        $dnssecRecordTypes = @(
            "NSEC"
            "NSEC3"
            "RRSIG"
            "DNSKEY"
            "DS"
            "CDNSKEY"
            "CDS"
            "NSEC3PARAM"
        );

        "Running 'Get-IbAdDnsDnssecRecord'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting DNSSEC records (NSEC, RRSIG, DS, DNSKEY, CDNSKEY, etc.) from the '$zoneName' zone on '$dnsServer' server." | Write-IbLogfile | Write-Verbose;

        try
        {
            $result = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zoneName -ErrorAction Stop | ?{$_.RecordType -in $dnssecRecordTypes};
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get DNS records from the server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }

        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsDnssecRecord'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsDnssecRecord.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsForwarderConfiguration.ps1
function Get-IbAdDnsForwarderConfiguration {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)][string]$dnsServer
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDnsForwarderConfiguration'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting the forwarding configuration for the '$dnsServer' DNS server." | Write-IbLogfile | Write-Verbose;

        #region Get general forwarding configuration
        try
        {
            $generalForwardingConfig = Get-DnsServerForwarder -ComputerName $dnsServer -ErrorAction Stop;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get general forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get general forwarding configuration


        #region Get conditional forwarding zones
        try
        {
            [array]$forwarderZones = Get-DnsServerZone -ComputerName $dnsServer | ?{$_.ZoneType -eq "Forwarder"};
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get conditional forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get conditional forwarding zones


        #region Generating resulting object
        $result = [pscustomobject]@{
            name = $dnsServer;
            general = $generalForwardingConfig.IPAddress;
            conditional = $forwarderZones;
        };
        #endregion /Generating resulting object


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsForwarderConfiguration'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsForwarderConfiguration.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsServer.ps1
function Get-IbAdDnsServer {
    [CmdletBinding()]
    param (
        # AD domain name (FQDN)
        [Parameter(Mandatory, ValueFromPipeline)][string]$domain
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting DNS servers in the '$domain' AD domain." | Write-IbLogfile | Write-Verbose;

        #region Get list of DNS servers
        try
        {
            $result = Get-DnsServerResourceRecord -RRType Ns -ComputerName $domain -ZoneName $domain `
                | ?{$_.HostName -eq "@"} -ErrorAction Stop `
                | %{$_.RecordData.NameServer.TrimEnd(".")};
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get the list of DNS servers for '$domain' domain.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get list of DNS servers

        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsServerQps.ps1
function Get-IbAdDnsServerQps {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)][string]$dnsServer
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDnsServerQps'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting QPS (queries per second) metric from '$dnsServer' DNS server." | Write-IbLogfile | Write-Verbose;

        #region Get statistics object
        try
        {
            $statistics = Get-DnsServerStatistics -ComputerName $dnsServer -ErrorAction Stop;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get DNS server statistics.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get statistics object


        [float]$qps = [Math]::Round($statistics.Query2Statistics.TotalQueries / $statistics.TimeStatistics.TimeElapsedSinceServerStart.TotalSeconds, 2);


        return $qps;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsServerQps'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsServerQps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsZone.ps1
function Get-IbAdDnsZone {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)][string]$dnsServer,

        # Get only 'external' zones
        [Parameter()][switch]$external,

        # Get only 'internal' zones
        [Parameter()][switch]$internal,

        # Ratio to identify if the zone is 'external' or 'internal'
        [Parameter()][float]$extIntRatio = 0.3,

        # Ratio to identify if the zone contain IPv6 records
        [Parameter()][float]$ipv6Ratio = 0.3,

        # Get only 'ipv6' zones
        [Parameter()][switch]$ipv6,

        # Get only 'forward' zones
        [Parameter(ParameterSetName = "Forward")][switch]$forward,

        # Get only 'reverse' zones
        [Parameter(ParameterSetName = "Reverse")][switch]$reverse
    );

    
    BEGIN {
        "Running 'Get-IbAdDnsZone'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;

        $privateIpv4Ranges = "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)";
        $privateIpv6Ranges = "^f[cd][0-9a-fA-F]{2}:"; # fc00::/7
        $localIpv6Ranges = "^fe[89abAB][0-9a-fA-F]:"; # fe80::/10
    }

    
    PROCESS {
        $result = $null;
        $zones = $null;
        $records = $null;


        #region Get all zones
        try
        {
            "Getting '$($PSCmdlet.ParameterSetName)' zones from the DNS server '$dnsServer'." | Write-IbLogfile | Write-Verbose;
            $zones = Get-DnsServerZone -ComputerName $dnsServer | ?{-not $_.IsAutoCreated -and $_.ZoneType -ne "Forwarder" -and $_.ZoneName -ne "TrustAnchors"};
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get zones from DNS server '$dnsServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get all zones


        #region Loop through zones and count A/AAAA records
        foreach ($zone in $zones)
        {
            #region Add properties to the object
            # Adding DnsServer property to results to use in other functions
            $zone | Add-Member -MemberType NoteProperty -Name "DnsServer" -Value $dnsServer;

            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_ext_zone" -Value $null;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_int_zone" -Value $null;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_ipv6_zone" -Value $null;

            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_records_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_ext_ipv4_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_int_ipv4_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_ext_ipv6_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_int_ipv6_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_loc_ipv6_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_ext_reverse_count" -Value 0;
            $zone | Add-Member -MemberType NoteProperty -Name "infbxl_int_reverse_count" -Value 0;
            #endregion /Add properties to the object


            #region Getting all records
            try
            {
                $records = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zone.ZoneName;    
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dns";
                    message = $_;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get records from '$($zone.ZoneName)' zone on '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
                $records = @();
            }
            #endregion /Getting all records


            #region Counting various types of records
            $zone.infbxl_records_count = $records | ?{$_.RecordType -in @("A", "AAAA", "PTR")} | Measure-Object | Select-Object -ExpandProperty Count;

            $zone.infbxl_int_ipv4_count = $records `
                | ?{ $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -match $privateIpv4Ranges } `
                | Measure-Object `
                | Select-Object -ExpandProperty Count;

            
            $zone.infbxl_ext_ipv4_count = $records `
                | ?{ $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -notmatch $privateIpv4Ranges } `
                | Measure-Object `
                | Select-Object -ExpandProperty Count;


            $zone.infbxl_ext_ipv6_count = $records `
                | ?{ $_.RecordType -eq "AAAA" -and $_.RecordData.IPv6Address -notmatch $privateIpv6Ranges -and $_.RecordData.IPv6Address -notmatch $localIpv6Ranges } `
                | Measure-Object `
                | Select-Object -ExpandProperty Count;


            $zone.infbxl_int_ipv6_count = $records `
                | ?{ $_.RecordType -eq "AAAA" -and $_.RecordData.IPv6Address -match $privateIpv6Ranges -and $_.RecordData.IPv6Address -notmatch $localIpv6Ranges } `
                | Measure-Object `
                | Select-Object -ExpandProperty Count;


            $zone.infbxl_loc_ipv6_count = $records `
                | ?{ $_.RecordType -eq "AAAA" -and $_.RecordData.IPv6Address -notmatch $privateIpv6Ranges -and $_.RecordData.IPv6Address -match $localIpv6Ranges } `
                | Measure-Object `
                | Select-Object -ExpandProperty Count;


            #region If the zone is reverse
            if ($zone.IsReverseLookupZone)
            {
                $zoneRangePrefix = $zone.ZoneName.split(".")[2] + "." + $zone.ZoneName.split(".")[1] + "." + $zone.ZoneName.split(".")[0] + ".";
                $zone.infbxl_ext_reverse_count = $records `
                    | ?{ $_.RecordType -eq "PTR" -and $zoneRangePrefix -notmatch $privateIpv4Ranges } `
                    | Measure-Object `
                    | Select-Object -ExpandProperty Count;

                $zone.infbxl_int_reverse_count = $records `
                    | ?{ $_.RecordType -eq "PTR" -and $zoneRangePrefix -match $privateIpv4Ranges } `
                    | Measure-Object `
                    | Select-Object -ExpandProperty Count;
            }
            #endregion /If the zone is reverse
            #endregion /Counting various types of records
        }
        #endregion /Loop through zones and count A/AAAA records


        #region Loop through zones and classify them
        foreach ($zone in $zones)
        {
            Write-Debug "zone = $($zone.ZoneName)";
            
            $isExternalRatio = ($zone.infbxl_ext_ipv4_count + $zone.infbxl_ext_ipv6_count + $zone.infbxl_ext_reverse_count) / ($zone.infbxl_records_count + 0.0000001);
            $isExternal = $isExternalRatio -ge $extIntRatio;
            Write-Debug "isExternalRatio = $isExternalRatio; isExternal = $isExternal";

            $isInternal = $isExternalRatio -lt $extIntRatio;
            Write-Debug "isExternalRatio = $isExternalRatio; isInternal = $isInternal";

            $isIpv6Ratio = ($zone.infbxl_ext_ipv6_count + $zone.infbxl_int_ipv6_count) / ($zone.infbxl_records_count + 0.0000001);
            $isIpv6 = $isIpv6Ratio -gt $ipv6Ratio;
            Write-Debug "isIpv6Ratio = $isIpv6Ratio; isIpv6 = $isIpv6";


            $zone.infbxl_ext_zone = $isExternal;
            $zone.infbxl_int_zone = $isInternal;
            $zone.infbxl_ipv6_zone = $isIpv6;
        }
        #endregion /Loop through zones and classify them


        #region Filter forward or reverse zones - or - leave result as is if no filter applied
        if ($forward)
        {
            "'forward' flag passed. Returning forward zones only." | Write-IbLogfile | Write-Verbose;
            [array]$result = $zones | ?{-not $_.IsReverseLookupZone};
        }
        elseif ($reverse)
        {
            "'reverse' flag passed. Returning reverse zones only." | Write-IbLogfile | Write-Verbose;
            [array]$result = $zones | ?{$_.IsReverseLookupZone};
        }
        else
        {
            [array]$result = $zones;
        }
        #endregion /Filter forward or reverse zones - or - leave result as is if no filter applied


        #region Filter 'external' zones
        if ($external)
        {
            "'external' flag passed. Returning 'external' zones." | Write-IbLogfile | Write-Verbose;
            [array]$result = $result | ?{ $_.infbxl_ext_zone };
        }
        #endregion /Filter 'external' zones


        #region Filter 'internal' zones
        if ($internal)
        {
            "'internal' flag passed. Returning 'internal' zones." | Write-IbLogfile | Write-Verbose;
            [array]$result = $result | ?{ $_.infbxl_int_zone };
        }
        #endregion /Filter 'internal' zones
        

        #region Filter 'ipv6' zones
        if ($ipv6)
        {
            "'ipv6' flag passed. Returning IPv6 zones only." | Write-IbLogfile | Write-Verbose;
            [array]$result = $result | ?{ $_.infbxl_ipv6_zone };
        }
        #endregion /Filter 'ipv6' zones


        "$($result.count) zones found." | Write-IbLogfile | Write-Verbose;
        
        
        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsZone'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsZone.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Select-IbAdDnsServer.ps1
function Select-IbAdDnsServer {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)][string]$dnsServer,

        # Return only 'external' servers
        [Parameter(ParameterSetName = "External")][switch]$external,

        # Return only 'internal' servers
        [Parameter(ParameterSetName = "Internal")][switch]$internal
    );

    
    BEGIN {
        "Running 'Select-IbAdDnsServer'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Checking if DNS server '$dnsServer' is 'internal' or 'external'." | Write-IbLogfile | Write-Verbose;

        
        $externalZones = $dnsServer | Get-IbAdDnsZone -external;


        if ($PSCmdlet.ParameterSetName -eq "External")
        {
            if ($externalZones)
            {
                return $dnsServer;
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "Internal")
        {
            if (-not $externalZones)
            {
                return $dnsServer;
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "All")
        {
            "No filter passed. Returning server by default." | Write-IbLogfile | Write-Verbose;
            return $dnsServer;
        }
        else
        {
            return $null;
        }
    }

    
    END {
        "Finished execution 'Select-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Select-IbAdDnsServer.ps1
#endregion /./_helpers/public/


#region ./_templates/common--main--body.ps1
$version = "1.0.5.0.tags-v1.0.5.b7b95e7";


$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss";
$result = @();


Set-IbLogfilePath -fileName "$dateTime.log";
Set-IbLogfilePath -fileName "$dateTime.pwsh.log" -powershellTranscript;
Set-IbCsvfilePath -fileName "$dateTime.csv";
"Script version: $version" | Write-IbLogfile | Write-Output;
Write-Output "";


#region Initialize global variables
$global:infoblox_errors = @();
#endregion /Initialize global variables


Start-Transcript -Path $env:INFOBLOX_PWSH_TRANSCRIPT_PATH;


#region Getting values for each metric and pushing them to CSV
@(
    "dhcp_server_count"
    "dhcp_lps"
    "dhcp_subnet_count"
    "dhcp_vendor"
    "dhcp_lease_time"
    "dhcp_device_count"
    "dns_ext_ipv6_used"
    "dns_int_ipv6_used"
    "dns_int_caching_forwarders"    
    "dns_ext_forward_zone_count"
    "dns_ext_reverse_zone_count"
    "dns_int_forward_zone_count"
    "dns_int_reverse_zone_count"
    "dns_ext_server_count"
    "dns_int_server_count"
    "gen_active_user"
    "gen_active_ip"
    "dns_ext_record_count"
    "dns_int_record_count"
    "dns_int_dnssec_used"
    "dns_ext_dnssec_used"
    "dns_int_vendor"
    "gen_vendor"
    "dns_int_qps"
    "dns_ext_qps"
    "dns_int_ad_domain_count"
    "gen_site_count"
) | %{
    $metric = $_;
    Write-Output "*** Start '$_' ***";
    $metric = & "infoblox_$_";
    $result += ,$metric;
    "Writing value to CSV file. '$metric'." | Write-IbLogfile | Write-Verbose;
    Export-IbCsv -array @(,$metric);
    Write-Output "*** Finished '$_' ***";
    Write-Output "";
};
#endregion /Getting values for each metric and pushing them to CSV


#region Reporting
if ($global:infoblox_errors.count -gt 0)
{
    "[!!!] There were '$($global:infoblox_errors.count)' errors during script execution. Please review log file: '$($env:INFOBLOX_SE_LOGPATH)'." | Write-IbLogfile -severity Warning | Write-Warning;
    "[!!!] Results provided in CSV file should not be considered as correct." | Write-IbLogfile -severity Warning | Write-Warning;

    "Here's the short report:" | Write-IbLogfile -severity Warning -noOutput;
    # "Here's the short report:" | Write-Warning;
    
    
    $global:infoblox_errors | Write-IbLogfile -severity Warning -noOutput;
    # $global:infoblox_errors | Out-String -Stream -Width 1000 | Write-Host;
}


"Report file available at: '$($env:INFOBLOX_SE_CSVPATH)'." | Write-IbLogfile | Write-Host;
"Log file available at: '$($env:INFOBLOX_SE_LOGPATH)'." | Write-IbLogfile | Write-Host;
"Powershell transcript file available at: '$($env:INFOBLOX_PWSH_TRANSCRIPT_PATH)'." | Write-IbLogfile | Write-Host;


"Script run finished." | Write-IbLogfile | Write-Host;


Stop-Transcript;
#endregion /Reporting
#endregion /./_templates/common--main--body.ps1


#region ./_templates/common--main--footer.ps1
#endregion /./_templates/common--main--footer.ps1

# SIG # Begin signature block
# MIIt8AYJKoZIhvcNAQcCoIIt4TCCLd0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBwMpU9UZZnIsMu
# INpcCPGXWnE4dyMmmQSbJ3wYwTBUn6CCE1wwggXAMIIEqKADAgECAhAP0bvKeWvX
# +N1MguEKmpYxMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNV
# BAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIEVWIFJvb3QgQ0EwHhcNMjIwMTEz
# MDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aa
# za57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllV
# cq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT
# +CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd
# 463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+
# EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92k
# J7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5j
# rubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7
# f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJU
# KSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+wh
# X8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQAB
# o4IBZjCCAWIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72NkK8MwDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMH8GCCsGAQUFBwEBBHMwcTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEkGCCsGAQUFBzAC
# hj1odHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJh
# bmNlRVZSb290Q0EuY3J0MEsGA1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwHAYD
# VR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQELBQADggEBAEHx
# qRH0DxNHecllao3A7pgEpMbjDPKisedfYk/ak1k2zfIe4R7sD+EbP5HU5A/C5pg0
# /xkPZigfT2IxpCrhKhO61z7H0ZL+q93fqpgzRh9Onr3g7QdG64AupP2uU7SkwaT1
# IY1rzAGt9Rnu15ClMlIr28xzDxj4+87eg3Gn77tRWwR2L62t0+od/P1Tk+WMieNg
# GbngLyOOLFxJy34riDkruQZhiPOuAnZ2dMFkkbiJUZflhX0901emWG4f7vtpYeJa
# 3Cgh6GO6Ps9W7Zrk9wXqyvPsEt84zdp7PiuTUy9cUQBY3pBIowrHC/Q7bVUx8ALM
# R3eWUaNetbxcyEMRoacwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wggbgMIIEyKADAgECAhAOMYeSwOZsiD0n3HzmRiweMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjAzMjM1OTU5WjBoMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIGA1UEBxMLU2FudGEg
# Q2xhcmExFjAUBgNVBAoTDUluZm9ibG94IEluYy4xFjAUBgNVBAMTDUluZm9ibG94
# IEluYy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDGF5mewcoeOXYD
# QMgzbD4vmqL+/EdPGIwaa63RYqMweTYPxoxEJv1y2G2Tk8rSBthhXz18oURwcGxm
# rhi2Q+ErTCtoo4AWmXpiRy7/X+xtJo9WcS/NtgDn58PnUAXK4zOsfY5dAq737grl
# 74kUY4CQnKniKpxYFWy9h4BDfnSfaDRQlIEMnm0mT2YbHCcm7MVMXrJLY3Gyfp3O
# 0ouqvJ+gIcvHfuR7cSmymNNbpNp5/azEYpe+4BhUiQ6eh51huwu8gLdHsuLrQFYl
# I3S8pcqTCqXK1TdXtngF0gFNhFH4PoRYOE4N3fQeZczhtLjbLrTmKcREfTGelapv
# PrfUH9XdDK0OCGnS4GlebYBwUoE2AhBfl3N+EbTL+GcGJL+1/6ONZJFRu/6pA49c
# RNrw77eUhlWUypP/BqmQUkwSPnt+hqmxKVcRLMIWf7W7GoE4Z1bQ88a8W3HJmZvM
# qseq5j9A7mQsDjD1qn9VpnKUk1a3zetunpbCn7XyKcL4i4i3itUCAwEAAaOCAgMw
# ggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRi
# yCql2Si1oRs+PCIJvtW6eeWc7jA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsG
# AQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQD
# AgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWdu
# aW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZT
# SEEzODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdS
# U0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
# AAOCAgEAgHAJos+P1CbYIq9ZNm3Ehn+ycx+KrVznJ6/znxKojVNCJtp/LXse/juv
# 9WtzbLCA3tPqzUh/VqRu5z/fC2rm123Iqrx/mYFNOd7T/7E5xbyqqZMYfo3o9D3F
# JYoOvE5bUDuFiuA71HsW83/SsKVTKYn4vgWbh1lnoJaCU4UJJoMRMi4i/zUU8J2c
# 4lnuX8SR/F0aWeqd1okfCmMEl928/RVjTkVNscLzV6MbdV02IoSbCkKMKnG9rDP5
# 0EdIxYYW/m03BYewM2w4RHZDj4IPj/hKzsy8AXI6lLKuB8ahoHg0kFh4lVBTLrq6
# D9S+fdp/VXqKxleZG+OSBEb8xtlaIYqOgXsB/sb0OP2wzvNjhDBQmsmG16NFQSip
# WpIykq8WPy9KxfqKHTtX5mvM56olnzyviSMZwyF66PgUHrZEIixQ1ar9bIjakFRH
# NjQdWrxfM4pCENHKFi/UmLeLXjWbnI79B7APdoZyJOwizAFOABB+s/kee7ndSAd+
# gEtcatJIbtsJSasvRluHK/gd9iG4JisZj3gGOppZ3iUmiZIud3yRzfa2HDDq3QB3
# QgpnlO+KR8+sFJUawOaoJ6L3gtlcaWeMPoRrE5ZqSozJOQiBHCVWl5hCzmAzCFMr
# qfm8F++BvkI6SybPcomp9cDnmu4bwTMiaEPdLZcgXwbS9+oZ3rcxghnqMIIZ5gIB
# ATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBT
# SEEzODQgMjAyMSBDQTECEA4xh5LA5myIPSfcfOZGLB4wDQYJYIZIAWUDBAIBBQCg
# fDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgNbFy
# 2PAEmeqC2rTQ0QkRFNJstrzOrjBe3f8iZzf4YWcwDQYJKoZIhvcNAQEBBQAEggGA
# qS3jci9c6yDpmtpWAyPB0E7bUHiDh/pPDE8sW0LQPdO/0km7OyperA6DkpdMoy/c
# WGrVVjoy5CY4t5Jf90RfAP3OxSpqRAG8htgzLF7RoIlNe1MiIQgVtJKjhK5JFe4t
# o5HJlZy14OzCnYCFiZYR+8rmKcnKyA5bPtDcHHElTeCiw/qpEwHw1DCF2c9DvlTI
# qqlf1cBHe37b8GAUoXFGmRac11a0+YKTan55/igrTUQehJJ4Ig7ZORgJBcUONW1P
# 70XocBsU/dyadD18RcNL/8xxP11rvKKPJ7RRr4eShd5/x5l4uWQcpRXgALE8WrA1
# 0jEIvNPOoTYg0z9KvzNs35uItrj2sPXHrPd5GwxXyXA6xBXMOTsZS8QxUolDqc8D
# kKRXW8lLFr+GuUVh24RfQc7bWcCX5EOIrmHkfxtjcLjqNqGETFCiIKljR6lgfBLL
# dZF0Rg89ESj4Xqn8DkqKabW3soaxghUKD31VCziE3bBgIHBExeKfaFOk0fvXkbkY
# oYIXQDCCFzwGCisGAQQBgjcDAwExghcsMIIXKAYJKoZIhvcNAQcCoIIXGTCCFxUC
# AQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYJYIZI
# AYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEINAUBOpb2OF5l+xzZ90luCcTWVXpBSUS
# 58KhZtygud1kAhEA5rCWin1X5QakK3ezzpel3xgPMjAyNDA0MTYxNjI2NDVaoIIT
# CTCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJKoZIhvcNAQELBQAw
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTlaMEgxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQg
# VGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCj
# U0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIVWMGpkxGnzaqyat0Q
# KYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9YrIBzBl5S0pVCB8s/L
# B6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5xXsQGmjzwxS55Dxtm
# UuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4KTlr4HhZl+NEK0rV
# lc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUdvJscsrdf3/Dudn0x
# mWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZBzcBkQ8ctVHNqkxm
# g4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02kefGRNnQ/fztFejKqr
# UBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1x4Nk1nXNjxJ2VqUk
# +tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhvltXhEBP+YUcKjP7w
# tsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPsCvERLmTgyyIryvEo
# EyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQABo4IBizCCAYcwDgYD
# VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUH
# AwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaA
# FLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T5+/N0GSh1VapZTGj
# 3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3Js
# MIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0Eu
# Y3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1PijxonNgl/8ss5M3q
# XSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09SI64a7p8Xb3CYTdo
# SXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5j9smViuw86e9NwzY
# mHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXTUOREEr4gDZ6pRND4
# 5Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08zjdSNd311RaGlWCZq
# A0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9NUvPJYCHEVkft2hFL
# jDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg21Llyln6XeThIX8rC
# 3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44OwdeOVj0fHMxVaCAEcsU
# DH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZruhf9xHdsFWyuq69z
# OuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7KP845VJa1qwXIiNO
# 9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywGRu9BHvDwX+Db2a2Q
# gESvgBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcN
# AQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8Ty
# kTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsm
# c5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTn
# KC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2
# R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0
# QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/
# oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1ps
# lPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhI
# fxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8
# I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkU
# EBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1G
# nrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSG
# Mmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQu
# Y3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0B
# AQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7
# cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2p
# Vs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxk
# Jodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpkn
# G6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2
# n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fm
# w0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvt
# Cl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU
# 5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8K
# vYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/
# GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAVE
# r/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0G
# CyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDA0MTYxNjI2NDVaMCsGCyqG
# SIb3DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3OqorJxk8ZnM9AMC8GCSqGSIb3
# DQEJBDEiBCCOOYGe1Wq1EWaBHzi8S8B4B5YDF0UyIfPa3F05a5WDNDA3BgsqhkiG
# 9w0BCRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZvgoraVZquMxavTRqa1Ax4
# KDANBgkqhkiG9w0BAQEFAASCAgCRMLLSV1Lg8ZjUzFkPEqtfevcNvBD6JH5MLCXB
# gYbcYQKWSlA0LN2Ys3tmjq4f+vbsUhLPhwuPhye2ABzLZZG4HrAjecrRRq7MKfMa
# ydX1jizAKCD42yPqRo06ci+hhVY70eDXxLwkL9uzV07xSDMN1L1++pLr1jccEbSb
# FIec8XeLh3pGdsZWeiH1ioj97Ze62++kQkEgZe3JgIzCILTGBwvLvrysczlM99yK
# N1Ej8/ENSjcSZBr+F0kRRh3KF7niFrSKyjAL2MbvMwpTUwektd3vW8TrJ1Rniv4i
# Gk9E/g0+10asKRgczu832szc0Tls2UGJNfUl5FjR/jnmCaFXUS3ZcOsV7HGTN4bY
# KnjeBXbTrfGTUyjnsdcwL5oglnvvwyP79MLWUO1/zgY/hFi9+lcZsyaMBR5E3myB
# R95ICRUHhYlfIM7dUiYyWJcgqT3byrEclIDUnIR0P4flO41IokpsSluZZvdQor25
# KGCX5i0IeGSFaamH+e8Ycq7ymX5FG5iJHmpjbQi6Yuag7nuSZnC43ygWptr6Uhvt
# td4Z9NCMde1h5USrqNA3CWqgFcjV5UsFDdBuBi/oH4lXWLQnvbuFmQSE3dFgKNDB
# vgjLJIhSrnGFFcSRZq+EwmNFErkn+mP58IzVOg2CnodfT91MOOmH3Q9H/uggutwO
# wBp34Q==
# SIG # End signature block
