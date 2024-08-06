<#
.NOTES
Copyright (C) 2019-2024 Infoblox Inc. All rights reserved.
Version: 1.0.8.0.tags-v1.0.8.823af3a


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

NOTE: If you decided to use administrative account to run the script, please ensure you're executing it from elevated command prompt. Otherwise, you may
      receive errors while running operations against DHCP and/or DNS services.

--

.NOTES

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


SUPPORTED PARAMETERS

This script supports several parameters, used to control the collection process and output verbosity. The list below provides a list of parameters
and example of usage.

!!! Important !!!
Please note that some of the supported parameters are mutually exclusive, meaning, you cannot provide some of them while others are also specified.
In such case, Powershell will print default error message:
    ```
        Parameter set cannot be resolved using the specified named parameters.
        One or more parameters issued cannot be used together or an insufficient number of parameters were provided.
    ```
    

    * -processOneMetricOnly <metric name>
        Provide this parameter to collect only one metric. The list of valid metrics can be found in this same FUNCTIONALITY section or it will be 
        printed in the error message if you provide unsupported metric name. This parameter is mutually exclusive with 'processDnsMetrics', 
        'processDhcpMetrics' and 'processGenMetrics' parameters.

    * -processDnsMetrics
        Switch-type parameter. Specify it to process DNS metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processDhcpMetrics
        Switch-type parameter. Specify it to process DHCP metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processGenMetrics
        Switch-type parameter. Specify it to process GEN metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -Verbose
        This is default switch-type parameter of Powershell used to enable verbose output to console. Use this to get more detailed information about
        what is happening during collection process.

#>


[CmdletBinding(DefaultParameterSetName = "All")]
param (
    # Process one metric, if specified
    [Parameter(ParameterSetName = "OneMetricOnly")]
    [string]
    $processOneMetricOnly,


    # Process DNS metrics
    [Parameter(ParameterSetName = "ProcessGenOrDnsOrDhcpMetrics")]
    [switch]
    $processDnsMetrics,


    # Process DHCP metrics
    [Parameter(ParameterSetName = "ProcessGenOrDnsOrDhcpMetrics")]
    [switch]
    $processDhcpMetrics,


    # Process GEN metrics
    [Parameter(ParameterSetName = "ProcessGenOrDnsOrDhcpMetrics")]
    [switch]
    $processGenMetrics
);


#region ./_templates/common--main--header.ps1
#endregion /./_templates/common--main--header.ps1


#region ./_helpers/public/
#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/dhcp_device_count.ps1
function infoblox_dhcp_device_count {
    <#
    .DESCRIPTION
        The script will return number of leases in all scopes (IPv4 and IPv6) in all DHCP servers in AD forest.
    #>

    [CmdletBinding()]
    param ();
    

    BEGIN {
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_device_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        [array]$dhcpServers = Get-IbAdDhcpServer;

        
        if ($dhcpServers)
        {
            [array]$ipv4Devices = $dhcpServers | Get-IbAdDhcpScope -ipv4 | ?{$_.State -eq "Active"} | %{
                Get-IbAdDhcpServerLease -dhcpServer $_.DhcpServer -scopeId $_.ScopeId -ipv4;
            }
            [array]$ipv6Devices = $dhcpServers | Get-IbAdDhcpScope -ipv6 | ?{$_.State -eq "Active"} | %{
                Get-IbAdDhcpServerLease -dhcpServer $_.DhcpServer -scopeId $_.ScopeId -ipv6;
            }


            [array]$result = $ipv4Devices + $ipv6Devices;
        }
        else
        {
            $result = @();
        }
        

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_lease_time'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        [array]$dhcpServers = Get-IbAdDhcpServer;


        if ($dhcpServers)
        {
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
        }
        else
        {
            $result = 0;
        }
        

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_lps'." | Write-IbLogfile | Write-Verbose;
    }

    PROCESS {
        [array]$dhcpServers = Get-IbAdDhcpServer;


        if ($dhcpServers)
        {
            [float]$result = $dhcpServers | Get-IbAdDhcpServerLps | Measure-Object -Average | Select-Object -ExpandProperty Average;
            [float]$result = [Math]::Round($result, 2);
        }
        else
        {
            $result = -2;
        }
        

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
        $result = $null;
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
        $result = $null;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dhcp_vendor'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = Get-IbAdForest | Select-Object -ExpandProperty ForestMode;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_dnssec_used'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
        [array]$dnssecRecords = $domains | Get-IbAdDnsServer | Select-Object -Unique | Get-IbAdDnsZone -forward -external | Get-IbAdDnsRecord -type Dnssec;

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_ipv6_used'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_qps'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_record_count'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $result = @();
        $domains = (Get-IbAdForest).Domains;
        [array]$zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -external | Get-IbAdDnsZone -external | Sort-Object -Unique -Property ZoneName;

        foreach ($zone in $zones)
        {
            $result += Get-IbAdDnsRecord -dnsServer $zone.DnsServer -zoneName $zone.ZoneName;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_ext_server_count'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_ad_domain_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        [array]$result = (Get-IbAdForest).Domains;

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_caching_forwarders'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_dnssec_used'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
        [array]$dnssecRecords = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -forward -internal | Get-IbAdDnsRecord -type Dnssec;

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_forward_zone_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_ipv6_used'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_qps'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
    <#
    .DESCRIPTION
        The function will return number of all DNS records from all 'internal' DNS zones from all DNS servers in the AD forest.
    #>
    
    [CmdletBinding()]
    param ();


    BEGIN {
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_record_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $result = @();
        $domains = (Get-IbAdForest).Domains;
        [array]$zones = $domains | Get-IbAdDnsServer | Select-Object -Unique | Select-IbAdDnsServer -internal | Get-IbAdDnsZone -internal | Sort-Object -Unique -Property ZoneName;

        foreach ($zone in $zones)
        {
            $result += Get-IbAdDnsRecord -dnsServer $zone.DnsServer -zoneName $zone.ZoneName;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_reverse_zone_count'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_server_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'dns_int_vendor'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $result = Get-IbAdForest | Select-Object -ExpandProperty ForestMode;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_active_ip'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $domains = (Get-IbAdForest).Domains;

        
        if ($domains)
        {
            [array]$adServers = $domains | %{ Get-IbAdServer -domain $_ };
            [array]$adControllers = $domains | %{ Get-IbAdDomainController -domain $_ };
            [array]$adWorkstations = $domains | %{ Get-IbAdWorkstation -domain $_ };

            [int]$result = $adServers.Count + $adControllers.Count + $adWorkstations.Count;
        }
        else
        {
            $result = 0;
        }

        
        return @("gen_active_ip", $result);
    }
    
    
    END {
        "[***] Finished collection 'gen_active_ip'." | Write-IbLogfile | Write-Verbose;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_active_user'." | Write-IbLogfile | Write-Verbose;
    }


    PROCESS {
        $domains = (Get-IbAdForest).Domains;

        
        if ($domains)
        {
            [array]$result = $domains | Get-IbAdUser -enabledOnly -excludeServiceAccounts;
        }
        else
        {
            $result = @();
        }
        
        return @("gen_active_user", $result.Count);
    }

    
    END {
        "[***] Finished collection 'gen_active_user'." | Write-IbLogfile | Write-Verbose;
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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_site_count'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $result = (Get-IbAdForest).Sites;

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
        $result = $null;
        " " | Write-IbLogfile | Write-Verbose;
        "[***] Collection 'gen_vendor'." | Write-IbLogfile | Write-Verbose;
    }
    

    PROCESS {
        $result = Get-IbAdForest | Select-Object -ExpandProperty ForestMode;
        return @("gen_vendor", $result);
    }
    

    END {
        "[***] Finished collection 'gen_vendor'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/@infoblox_collection/gen_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdDomainController.ps1
function Get-IbAdDomainController {
    [CmdletBinding()]
    param (
        # Domain name
        [Parameter(Mandatory)]
        [string]
        $domainName,

        # Filter by Global Catalog role
        [Parameter()]
        [switch]
        $globalCatalog
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
                message = $_.Exception.Message;
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


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdForest.ps1
function Get-IbAdForest {
    [CmdletBinding()]
    param (
        
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdForest'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        try
        {
            $result = Get-ADForest;
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get AD Dorest details.`n`t$_`n`tPowershell could not connect to any AD domain controller.`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get AD Dorest details.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        

        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdForest'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdForest.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_common/Get-IbAdServer.ps1
function Get-IbAdServer {
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
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $domain,

        # User ADSI queries instead of Powershell
        [Parameter()]
        [switch]
        $useAdsi
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
                    message = $_.Exception.Message;
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
                message = $_.Exception.Message;
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
        [Parameter()]
        [string[]]
        $properties = @("name"),

        # Search for disabled users only
        [Parameter(ParameterSetName = "DisabledOnly")]
        [switch]
        $disabledOnly,

        # Search for enabled users only
        [Parameter(ParameterSetName = "EnabledOnly")]
        [switch]
        $enabledOnly,

        # Exclude accounts with names finishing with 'SvcAccount'
        [Parameter()]
        [switch]
        $excludeServiceAccounts,

        # DC to connect to
        [Parameter(ValueFromPipeline)]
        [string]
        $server
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
                message = $_.Exception.Message;
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
                    message = $_.Exception.Message;
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


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Get-IbCimExceptionCustomErrorMessage.ps1
function Get-IbCimExceptionCustomErrorMessage {
    [CmdletBinding()]
    param (
        # Value of $_.Exception.MessageId
        [Parameter()]
        [Microsoft.Management.Infrastructure.CimException]
        $exception
    );

    
    BEGIN {}

    
    PROCESS {
        $defaultText = "Error code: '$($exception.MessageId)'. ";
        $defaultText += $exception.ErrorData.CimInstanceProperties | ?{$_.name -eq "error_WindowsErrorMessage"} | Select-Object -ExpandProperty Value;
        $defaultText += "`n`t";

        switch ($exception.MessageId) {
            "WIN32 4"       { $result = $defaultText + "The issue could be on local computer or remote server. Too many opened files in the system, hence request cannot be completed."; }
            "WIN32 5"       { $result = $defaultText + "Current user does not have permissions to read from the server."; }
            "WIN32 1721"    { $result = $defaultText + "Most likely the server or local computer does not have free resources (usually - memory) to process the request."; }
            "WIN32 1722"    { $result = $defaultText + "Most likely the server is turned off or not accessible through network."; }
            "WIN32 1723"    { $result = $defaultText + "Most likely the server is experiencing heavy load."; }
            "DHCP 20070"    { $result = $defaultText + "Powershell module could not connect to any AD controller."; }
            Default         { $result = $defaultText + "--- No detailed explanation ---"; }
        }

        return $result;
    }

    
    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/Get-IbCimExceptionCustomErrorMessage.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/New-IbCsMetricsList.ps1
function New-IbCsMetricsList {
    [CmdletBinding()]
    param (
        # Process one metric, if specified
        [Parameter()]
        [AllowEmptyString()]
        [string]
        $customMetricName,

        # Process DNS metrics
        [Parameter()]
        [switch]
        $processDnsMetrics,

        # Process DHCP metrics
        [Parameter()]
        [switch]
        $processDhcpMetrics,

        # Process GEN metrics
        [Parameter()]
        [switch]
        $processGenMetrics
    );

    
    BEGIN {
        "Running 'Get-IbCsMetricsList'." | Write-IbLogfile | Write-Verbose;

        "Building metrics list to process." | Write-IbLogfile | Write-Verbose;


        $defaultMetricsToProcess = @(
            "dhcp_device_count"
            "dhcp_lease_time"
            "dhcp_lps"
            "dhcp_server_count"
            "dhcp_subnet_count"
            "dhcp_vendor"
            "dns_ext_dnssec_used"
            "dns_ext_forward_zone_count"
            "dns_ext_ipv6_used"
            "dns_ext_qps"
            "dns_ext_record_count"
            "dns_ext_reverse_zone_count"
            "dns_ext_server_count"
            "dns_int_ad_domain_count"
            "dns_int_caching_forwarders"
            "dns_int_dnssec_used"
            "dns_int_forward_zone_count"
            "dns_int_ipv6_used"
            "dns_int_qps"
            "dns_int_record_count"
            "dns_int_reverse_zone_count"
            "dns_int_server_count"
            "dns_int_vendor"
            "gen_active_ip"
            "gen_active_user"
            "gen_site_count"
            "gen_vendor"
        );
    }

    
    PROCESS {
        if ($customMetricName)
        {
            if ($customMetricName -in $defaultMetricsToProcess)
            {
                "Metric '$customMetricName' will be processed only as per 'processOneMetricOnly' parameter." | Write-IbLogfile | Write-Verbose;
                $metricsToProcess = @($customMetricName);
            }
            else
            {
                "Value, provided for 'processOneMetricOnly' parameter, is incorrect. Please consult with help section." | Write-IbLogfile -severity Error | Write-Error;
                "List of supported metrics:`n$defaultMetricsToProcess" | Out-String | Write-IbLogfile -severity Error | Write-Error;
                $metricsToProcess = @();
            }
        }
        else
        {
            $metricsToProcess = @();


            if ($processDnsMetrics)
            {
                $metricsToProcess += $defaultMetricsToProcess | ?{$_ -match "^dns_"};
                "DNS metrics are added to the list." | Write-IbLogfile | Write-Verbose;
            }
            if ($processDhcpMetrics)
            {
                $metricsToProcess += $defaultMetricsToProcess | ?{$_ -match "^dhcp_"};
                "DHCP metrics are added to the list." | Write-IbLogfile | Write-Verbose;
            }
            if ($processGenMetrics)
            {
                $metricsToProcess += $defaultMetricsToProcess | ?{$_ -match "^gen_"};
                "GEN metrics are added to the list." | Write-IbLogfile | Write-Verbose;
            }
        }


        return $metricsToProcess;
    }

    
    END {
        "Finished execution 'Get-IbCsMetricsList'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/common/New-IbCsMetricsList.ps1


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
        New-Item -Path "$csvPath/$fileName" -Force | Out-Null;
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
            New-Item -Path "$logPath/$fileName" -Force | Out-Null;
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
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullorEmpty()]
        [string]
        $text,

        # Message severity passed to the log
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [ValidateSet("Info", "Error", "Warning")]
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


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsForwarderConfiguration.ps1
function Get-IbAdDnsForwarderConfiguration {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $dnsServer
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get general forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get general forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Get general forwarding configuration


        #region Get conditional forwarding zones
        try
        {
            [array]$forwarderZones = Get-DnsServerZone -ComputerName $dnsServer | ?{$_.ZoneType -eq "Forwarder"};
        }
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get conditional forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get conditional forwarding configuration for the '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsRecord.ps1
function Get-IbAdDnsRecord {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]
        $dnsServer,

        # DNS server forward zone
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]
        $zoneName,

        # DNS record type to return
        [Parameter()]
        [ValidateSet("All", "Dnssec", "A", "AAAA", "PTR", "Ns")]
        [string]
        $type = "All"
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDnsRecord'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        #region Prepare parameters for the 'Get-DnsServerResourceRecord' cmdlet depending on the provided request
        $params = @(
            [hashtable]@{
                ComputerName = $dnsServer;
                ZoneName = $zoneName;
            }
        );


        if ($type -eq "All")
        {
            "Getting '$type' records from the '$zoneName' zone on '$dnsServer' server." | Write-IbLogfile | Write-Verbose;
        }


        if ($type -eq "Dnssec")
        {
            "Getting DNSSEC records (NSEC, RRSIG, DS, DNSKEY, CDNSKEY, etc.) from the '$zoneName' zone on '$dnsServer' server." | Write-IbLogfile | Write-Verbose;

            $dnssecRecordTypes = @(
                "NSEC",
                "NSEC3",
                "RRSIG",
                "DNSKEY",
                "DS",
                "NSEC3PARAM"
            );

            $params = $dnssecRecordTypes | %{
                [hashtable]@{
                    ComputerName = $dnsServer;
                    ZoneName = $zoneName;
                    RRType = $_;
                };
            };
        }


        if ($type -notin @("All", "Dnssec"))
        {
            "Getting '$type' records from the '$zoneName' zone on '$dnsServer' server." | Write-IbLogfile | Write-Verbose;
            $params[0].RRType = $type;
        }
        #endregion /Prepare parameters for the 'Get-DnsServerResourceRecord' cmdlet depending on the provided request


        #region Execute 'Get-DnsServerResourceRecord'
        try
        {
            [array]$result = $params | %{
                Get-DnsServerResourceRecord @_ -ErrorAction Stop;
            };
        }
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get DNS records from the server.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get DNS records from the server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Execute 'Get-DnsServerResourceRecord'


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsRecord'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsRecord.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dns/Get-IbAdDnsServer.ps1
function Get-IbAdDnsServer {
    [CmdletBinding()]
    param (
        # AD domain name (FQDN)
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $domain
    );

    
    BEGIN {
        $result = $null;
        "Running 'Get-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Getting DNS servers in the '$domain' AD domain." | Write-IbLogfile | Write-Verbose;

        #region Get list of DNS servers
        [array]$result = Get-IbAdDnsRecord -dnsServer $domain -zoneName $domain -type Ns `
            | ?{$_.HostName -eq "@"} `
            | %{$_.RecordData.NameServer.TrimEnd(".")};
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
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $dnsServer
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get DNS server statistics.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get DNS server statistics.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get zones from DNS server '$dnsServer'.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get zones from DNS server '$dnsServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
            $records = @("A", "AAAA", "PTR") | %{
                Get-IbAdDnsRecord -dnsServer $dnsServer -zoneName $zone.ZoneName -type $_;
            };
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
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $dnsServer,

        # Return only 'external' servers
        [Parameter(ParameterSetName = "External")]
        [switch]
        $external,

        # Return only 'internal' servers
        [Parameter(ParameterSetName = "Internal")]
        [switch]
        $internal
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


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpScope.ps1
function Get-IbAdDhcpScope {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        # DHCP server FQDN
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]
        $dhcpServer,
        
        # Get only 'ipv4' scopes
        [Parameter(ParameterSetName = "ipv4")]
        [switch]
        $ipv4,

        # Get only 'ipv6' scopes
        [Parameter(ParameterSetName = "ipv6")]
        [switch]
        $ipv6
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            $explanation = Get-IbCimExceptionCustomErrorMessage -exception $_.Exception;
            "Error while trying to get scopes from DHCP server '$dhcpServer'.`n`t$_`n`t$explanation`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get scopes from DHCP server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
        [Parameter()]
        [switch]
        $doNotTestService
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get the list of DHCP servers from AD`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dhcp";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get the list of DHCP servers from AD.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        #endregion /Getting DHCP servers using Powershell


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServerLease.ps1
function Get-IbAdDhcpServerLease {
    [CmdletBinding(DefaultParameterSetName = "All")]
    param (
        # DHCP server
        [Parameter(Mandatory)]
        [string]
        $dhcpServer,

        # Scope ID
        [Parameter(Mandatory)]
        [string]
        $scopeId,

        # IPv4
        [Parameter(ParameterSetName = "ipv4")]
        [switch]
        $ipv4,

        # IPv6
        [Parameter(ParameterSetName = "ipv6")]
        [switch]
        $ipv6
    );

    
    BEGIN {
        "Running 'Get-IbAdDhcpServerLease'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        #region IPv4 leases
        if ($ipv4)
        {
            try
            {
                $result = Get-DhcpServerv4Lease -ComputerName $dhcpServer -scopeid $scopeId;
            }
            catch [Microsoft.Management.Infrastructure.CimException]
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                $explanation = Get-IbCimExceptionCustomErrorMessage -exception $_.Exception;
                "Error while trying to get leases from DHCP server '$dhcpServer', '$scopeId' scope.`n`t$_`n`t$explanation`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to get leases from DHCP server '$dhcpServer', '$scopeId' scope.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
        }
        #endregion /IPv4 leases


        #region IPv6 leases
        if ($ipv6)
        {
            try
            {
                $result = Get-DhcpServerv6Lease -ComputerName $dhcpServer -scopeid $scopeId;
            }
            catch [Microsoft.Management.Infrastructure.CimException]
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                $explanation = Get-IbCimExceptionCustomErrorMessage -exception $_.Exception;
                "Error while trying to get leases from DHCP server '$dhcpServer', '$scopeId' scope.`n`t$_`n`t$explanation`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to get leases from DHCP server '$dhcpServer', '$scopeId' scope.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
        }
        #endregion /IPv6 leases
        
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServerLease'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServerLease.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/_helpers/public/ad_dhcp/Get-IbAdDhcpServerLps.ps1
function Get-IbAdDhcpServerLps {
    [CmdletBinding()]
    param (
        # DHCP server
        [Parameter(ValueFromPipeline, Mandatory)]
        [string]
        $dhcpServer
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
            catch [Microsoft.Management.Infrastructure.CimException]
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get DHCP server IPv4 statistics from the server '$dhcpServer'.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to get DHCP server IPv4 statistics from the server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            #endregion /Getting IPv4 statistics


            #region Getting IPv6 statistics
            try
            {
                "Getting DHCP server IPv6 statistics." | Write-IbLogfile | Write-Verbose;
                $ipv6Stats = Get-DhcpServerv6Statistics -ComputerName $dhcpServer -ErrorAction Stop;
            }
            catch [Microsoft.Management.Infrastructure.CimException]
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get DHCP server IPv6 statistics from the server '$dhcpServer'.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dhcp";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to get DHCP server IPv6 statistics from the server '$dhcpServer'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
#endregion /./_helpers/public/


#region ./_templates/common--main--body.ps1
$version = "1.0.8.0.tags-v1.0.8.823af3a";


$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss";
$result = @();


Set-IbLogfilePath -fileName "$dateTime.log";
Set-IbLogfilePath -fileName "$dateTime.pwsh.log" -powershellTranscript;
Set-IbCsvfilePath -fileName "$dateTime.csv";
Write-Output " ";
"Script version: $version" | Write-IbLogfile | Write-Output;
Write-Output "";


#region Initialize global variables
$global:infoblox_errors = @();
#endregion /Initialize global variables


Start-Transcript -Path $env:INFOBLOX_PWSH_TRANSCRIPT_PATH;


#region Define metrics to collect
$params = @{
    customMetricName = $processOneMetricOnly;
    processDnsMetrics = $processDnsMetrics;
    processDhcpMetrics = $processDhcpMetrics;
    processGenMetrics = $processGenMetrics;
};

$metricsToProcess = New-IbCsMetricsList @params;

if ($metricsToProcess.count -gt 1) { "Metrics to be collected:`n$($metricsToProcess)" | Write-IbLogfile | Write-Output; }
#endregion /Define metrics to collect


#region Getting values for each metric and pushing them to CSV
$metricsToProcess | %{
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
    $global:infoblox_errors | Write-IbLogfile -severity Warning -noOutput;
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
