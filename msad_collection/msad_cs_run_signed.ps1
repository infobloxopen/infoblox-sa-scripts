<#
.NOTES
Copyright (C) 2019-2024 Infoblox Inc. All rights reserved.
Version: 1.0.7.0.tags-v1.0.7.c66ebbe


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
        Swith-type parameter. Specify it to process DNS metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processDhcpMetrics
        Swith-type parameter. Specify it to process DHCP metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processGenMetrics
        Swith-type parameter. Specify it to process GEN metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

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
            "WIN32 1722"    { $result = $defaultText + "Most likely the server is turned off or not accessible through network."; }
            "WIN32 5"       { $result = $defaultText + "Current user does not have permissions to read from the server."; }
            Default         { $result = $defaultText + "Unkown error."; }
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
                message = $_.Exception.Message;
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
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while trying to get the list of DNS servers for '$domain' domain.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to get the list of DNS servers for '$domain' domain.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
            try
            {
                $records = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zone.ZoneName;    
            }
            catch [Microsoft.Management.Infrastructure.CimException]
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dns";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Error while trying to get records from '$($zone.ZoneName)' zone on '$dnsServer' server.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "ad_dns";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to get records from '$($zone.ZoneName)' zone on '$dnsServer' server.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
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
                message = $_.Exception.Message;
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
                message = $_.Exception.Message;
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
                    message = $_.Exception.Message;
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
                    message = $_.Exception.Message;
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
#endregion /./_helpers/public/


#region ./_templates/common--main--body.ps1
$version = "1.0.7.0.tags-v1.0.7.c66ebbe";


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

# SIG # Begin signature block
# MIIoKwYJKoZIhvcNAQcCoIIoHDCCKBgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCzGOQuzTCejYeI
# Hu21PHvH60dqxm97p4/FVd4h7snfZKCCDZgwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggbgMIIEyKADAgECAhAOMYeSwOZsiD0n3HzmRiweMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjAz
# MjM1OTU5WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEUMBIG
# A1UEBxMLU2FudGEgQ2xhcmExFjAUBgNVBAoTDUluZm9ibG94IEluYy4xFjAUBgNV
# BAMTDUluZm9ibG94IEluYy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
# gQDGF5mewcoeOXYDQMgzbD4vmqL+/EdPGIwaa63RYqMweTYPxoxEJv1y2G2Tk8rS
# BthhXz18oURwcGxmrhi2Q+ErTCtoo4AWmXpiRy7/X+xtJo9WcS/NtgDn58PnUAXK
# 4zOsfY5dAq737grl74kUY4CQnKniKpxYFWy9h4BDfnSfaDRQlIEMnm0mT2YbHCcm
# 7MVMXrJLY3Gyfp3O0ouqvJ+gIcvHfuR7cSmymNNbpNp5/azEYpe+4BhUiQ6eh51h
# uwu8gLdHsuLrQFYlI3S8pcqTCqXK1TdXtngF0gFNhFH4PoRYOE4N3fQeZczhtLjb
# LrTmKcREfTGelapvPrfUH9XdDK0OCGnS4GlebYBwUoE2AhBfl3N+EbTL+GcGJL+1
# /6ONZJFRu/6pA49cRNrw77eUhlWUypP/BqmQUkwSPnt+hqmxKVcRLMIWf7W7GoE4
# Z1bQ88a8W3HJmZvMqseq5j9A7mQsDjD1qn9VpnKUk1a3zetunpbCn7XyKcL4i4i3
# itUCAwEAAaOCAgMwggH/MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5C
# MB0GA1UdDgQWBBRiyCql2Si1oRs+PCIJvtW6eeWc7jA+BgNVHSAENzA1MDMGBmeB
# DAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
# DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0w
# gaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1o
# dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2ln
# bmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcw
# AoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADAN
# BgkqhkiG9w0BAQsFAAOCAgEAgHAJos+P1CbYIq9ZNm3Ehn+ycx+KrVznJ6/znxKo
# jVNCJtp/LXse/juv9WtzbLCA3tPqzUh/VqRu5z/fC2rm123Iqrx/mYFNOd7T/7E5
# xbyqqZMYfo3o9D3FJYoOvE5bUDuFiuA71HsW83/SsKVTKYn4vgWbh1lnoJaCU4UJ
# JoMRMi4i/zUU8J2c4lnuX8SR/F0aWeqd1okfCmMEl928/RVjTkVNscLzV6MbdV02
# IoSbCkKMKnG9rDP50EdIxYYW/m03BYewM2w4RHZDj4IPj/hKzsy8AXI6lLKuB8ah
# oHg0kFh4lVBTLrq6D9S+fdp/VXqKxleZG+OSBEb8xtlaIYqOgXsB/sb0OP2wzvNj
# hDBQmsmG16NFQSipWpIykq8WPy9KxfqKHTtX5mvM56olnzyviSMZwyF66PgUHrZE
# IixQ1ar9bIjakFRHNjQdWrxfM4pCENHKFi/UmLeLXjWbnI79B7APdoZyJOwizAFO
# ABB+s/kee7ndSAd+gEtcatJIbtsJSasvRluHK/gd9iG4JisZj3gGOppZ3iUmiZIu
# d3yRzfa2HDDq3QB3QgpnlO+KR8+sFJUawOaoJ6L3gtlcaWeMPoRrE5ZqSozJOQiB
# HCVWl5hCzmAzCFMrqfm8F++BvkI6SybPcomp9cDnmu4bwTMiaEPdLZcgXwbS9+oZ
# 3rcxghnpMIIZ5QIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEA4xh5LA5myIPSfcfOZGLB4wDQYJ
# YIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQg2N/yzqlKnbaXsPtPWcUCCoRMmMUDFYsQzV+m/Tjh7cEwDQYJKoZI
# hvcNAQEBBQAEggGAENqMywerWuD16d+vzv1AQAItBVyFvl+Pxu9lXTBDTm/C5spJ
# oJsoWagwwso/5XWrRBy+xwHWUpbj5Pm8hwLUsELFOGEiaHXYwtI0GDQqFigPyuQw
# 25Cs7ZiZc6S6XA2RBKet6ILoGTcZjxhmlfwLbOtZtu6Gi0LDJewSfW9DmOJ43a/E
# 0X0KdnMfEhGtUer2xWG6psAXw5BCgRW/tqEzlapGwcIBehk2wv5aNjOb9R7eujmO
# GKTLbFu1VURxB1CG3M4m6NUFAxe97b8SWCuqs22xlhCPebsZsj2vNfGOjkNi7Xe7
# IAdoyrqsJe1ssiPYbSNbBa/EkwQ42DwjfX9O/nRCX211eiCiDo39txhA+vNauOUX
# 9Wa5zDaWn8e8JD1ZFSeBT7TyZBJxylmN+byZuXCo/TNI4WONazfXr81Z+c4eu63P
# yJza8bxeI2MI4t4sz/c4cqD/qhW8D4kYTLbC09J4E/yt7fiU3s+7UND1/SG2UPA2
# NajPV+kOSCm63cSuoYIXPzCCFzsGCisGAQQBgjcDAwExghcrMIIXJwYJKoZIhvcN
# AQcCoIIXGDCCFxQCAQMxDzANBglghkgBZQMEAgEFADB3BgsqhkiG9w0BCRABBKBo
# BGYwZAIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIPP+mUiIbSiO4oFA
# Uv7df1P9e9jfxEQtGmg9Fb+YQ5TsAhBn8DlN6Gfa0XblRzaFQuZSGA8yMDI0MDgw
# NTE2Mzk1NlqgghMJMIIGwjCCBKqgAwIBAgIQBUSv85SdCDmmv9s/X+VhFjANBgkq
# hkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYg
# VGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAwMDAwMFoXDTM0MTAxMzIzNTk1OVow
# SDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSAwHgYDVQQD
# ExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X5dLnXaEOCdwvSKOXejsqnGfcYhVY
# wamTEafNqrJq3RApih5iY2nTWJw1cb86l+uUUI8cIOrHmjsvlmbjaedp/lvD1isg
# HMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa2mq62DvKXd4ZGIX7ReoNYWyd/nFe
# xAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgtXkV1lnX+3RChG4PBuOZSlbVH13gp
# OWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60pCFkcOvV5aDaY7Mu6QXuqvYk9R28
# mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17cz4y7lI0+9S769SgLDSb495uZBkH
# NwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BYQfvYsSzhUa+0rRUGFOpiCBPTaR58
# ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9c33u3Qr/eTQQfqZcClhMAD6FaXXH
# g2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw9/sqhux7UjipmAmhcbJsca8+uG+W
# 1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2ckpMEtGlwJw1Pt7U20clfCKRwo+wK
# 8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhRB8qUt+JQofM604qDy0B7AgMBAAGj
# ggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# HwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYDVR0OBBYEFKW27xPn
# 783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3Rh
# bXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZTSEEyNTZUaW1l
# U3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAIEa1t6gqbWYF7xwjU+K
# PGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF7SaCinEvGN1Ott5s1+FgnCvt7T1I
# jrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrCQDifXcigLiV4JZ0qBXqEKZi2V3mP
# 2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFcjGnRuSvExnvPnPp44pMadqJpddNQ
# 5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8wWkZus8W8oM3NG6wQSbd3lqXTzON
# 1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbFKNOt50MAcN7MmJ4ZiQPq1JE3701S
# 88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP4xeR0arAVeOGv6wnLEHQmjNKqDbU
# uXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VPNTwAvb6cKmx5AdzaROY63jg7B145
# WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvrmoI1VygWy2nyMpqy0tg6uLFGhmu6
# F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2obhDLN9OTH0eaHDAdwrUAuBcYLso
# /zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJuEbTbDJ8WC9nR2XlG3O2mflrLAZG
# 70Ee8PBf4NvZrZCARK+AEEGKMIIGrjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipe
# WzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1
# OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5
# BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0
# YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1Bkmz
# wT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkL
# f50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C
# 3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5
# n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUd
# zTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWH
# po9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/
# oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPV
# A+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg
# 0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mM
# DDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6E
# VO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBT
# zr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/E
# UExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fm
# niye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szw
# cqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8TH
# wcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/
# JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9
# Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm
# 228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVB
# tzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnw
# ZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv2
# 7dZ8/DCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zC
# pyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf
# 1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x
# 4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEio
# ZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7ax
# xLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZ
# OjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJ
# l2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz
# 2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH
# 4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb
# 5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ
# 9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuC
# MS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0g
# ADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs
# 7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq
# 3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/
# Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9
# /HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWoj
# ayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3YwggNyAgEB
# MHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFt
# cGluZyBDQQIQBUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKCB0TAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI0MDgwNTE2
# Mzk1NlowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUZvArMsLCyQ+CXc6qisnGTxmc
# z0AwLwYJKoZIhvcNAQkEMSIEIDDO1ih5GXhdEvzmcH5M6S4kjpu3ptMRPulJ8/12
# 7HBKMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEINL25G3tdCLM0dRAV2hBNm+CitpV
# mq4zFq9NGprUDHgoMA0GCSqGSIb3DQEBAQUABIICAIKa7UNGuCULppwYbL/8OGsq
# ilKDF/yJUMK8WAo1tP6h7h9FqFd7JYd7KgMoLvn++TFhKkWqMgHXlVs+/yim6Lkx
# bYYYhN5vRnUp/V8JfMQ21CYuloSooC8ggUQPILIorxzdTaqCA296a9gYz1I2ozSq
# 7MmWqLANQa5lS+cHzGyJ7uHmpGf8aGw8hhb8CgOrtp+fGSYWChYWkOGts+Rqtoll
# 0KpeQi3Ne4rLiFMZRK7YCW02Xyembw8RkjNKtTMbVsZNpQozitp1hfXY5CIiRVxu
# aGHoAvOcCJ0716r6CVJQCsFDSwBg5oJq4VRJKgczK/S5N1Wn1LoYRZYrLpbk2NrD
# EefgS1pl3hVct66pYPO+nzrLS3E29B2w8kwaKZFIeAWqlvaks7+32fkYxSFyMryw
# tqPQHMlcDJnShAPyi7wJK29BiFoHIXYFZ2mJAO1ED19x50BpzeOOjbs5h9CLzWcj
# TKMHb6/gdH0dekRtohmQv2cICayB/hY0a63JKaRJhdLHzf6hcRIMZQGB2h7mK5Pb
# U8Z+vxnKKtqLRhsSwuugPAL8YPdGxnL2ufEf/wU21foFwMfOoEA4n1bxwTQulGPB
# z+ZWYNJCvxelavF8MJaRJvqlpkQqMAGisIJPO0odNP4rjdVAuVCk52EQ4az4ubXi
# ZmDWddGijCqTdDifU6Wq
# SIG # End signature block
