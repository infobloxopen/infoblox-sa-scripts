# MSAD Collection Script

## SYNOPSIS

Copyright (C) 2019-2024 Infoblox Inc. All rights reserved.  
Version: 1.1.1.0.main.84bb2f8

This is a script developed to collect various data about AD/DNS/DHCP infrastructure. Data collected includes basic information about AD topology,
computers, user accounts; DNS zones, records and statistics; DHCP scopes, leases and statistics.  
[!!!] Please review NOTES section of the help to check on detailed functionality implemented by the script.

The script can be run on any Windows domain-joined machine.  
[!!!] Please review DESCRIPTION section of the help to check on preprequisites that must be met before running the script.

The script do not run any create/update operation, only read ones, hence ONLY READ permissions are required for the user account that will run the script.  
[!!!] Please review DESCRIPTION section of the help to check on detailed permissions that the user account must have before running the script.

There are some advanced features of this collection script, mainly used for troubleshooting or to provide additional verbosity to output.  
Please review NOTES section of the help to get details of supported parameters.


## DESCRIPTION

To run this tool, perform the following steps:  

1. Log on to a Windows machine where you plan to run the script.
 
2. Ensure that all pre-requisites are met to run the script.
 
3. Copy script to a writable directory where the output files are to be stored and CD to it using Powershell console.
 
4. Run the script.
 
5. Examine output for errors (in the same console window or in the log file in the ./@logs/ directory).
 
6. Logs will be created in the ./@logs/ directory, output file - in the ./@output/ directory.
 


PRE-REQUISITES:

The script is supporting Powershell 5.1 or later.

It's mandatory that you run this script on the server with several Management Tools installed.
 
You can check if you have them installed by running these commands:

    Windows Desktop systems (run in elevated Powershell console):
    - Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools" -Online | Select-Object State
    - Get-WindowsCapability -Name "Rsat.DHCP.Tools" -Online | Select-Object State
    - Get-WindowsCapability -Name "Rsat.DNS.Tools" -Online | Select-Object State

    Windows Server systems:
    - Get-WindowsFeature -name "RSAT-AD-PowerShell"
    - Get-WindowsFeature -name "RSAT-ADDS"
    - Get-WindowsFeature -name "RSAT-ADLDS"
    - Get-WindowsFeature -name "RSAT-DHCP"
    - Get-WindowsFeature -name "RSAT-DNS-Server"


You can install them by running these commands:

    Windows Desktop systems (run in elevated Powershell console):
    - Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools" -Online
    - Add-WindowsCapability -Name "Rsat.DHCP.Tools" -Online
    - Add-WindowsCapability -Name "Rsat.DNS.Tools" -Online

    Windows Server systems:
    - Add-WindowsFeature -name "RSAT-AD-PowerShell"
    - Add-WindowsFeature -name "RSAT-ADDS"
    - Add-WindowsFeature -name "RSAT-ADLDS"
    - Add-WindowsFeature -name "RSAT-DHCP"
    - Add-WindowsFeature -name "RSAT-DNS-Server"

Before collecting metrics, the script will check if all pre-requisites are installed on the current machine.
If anything is missing - script will report
an error and halt any further work.

--

LOCAL PERMISSIONS:

If you're running the script under a non-administrator user account on Windows machine, this account must have write permissions on the
folder where the script is located.
This is required to write resulting CSV file and log files.

--

ACTIVE DIRECTORY / DHCP / DNS PERMISSIONS:

In general, the easiest way to get sufficient permissions in AD/DHCP/DNS - is to run the script under user account that has either 
'Domain Administrators' or 'Enterprise Administrators' membership (depending on the Active Directory topology).
However, it's not recommended approach for the 
Active Directory.
 
If you're going to execute the script under limited user account, please check that it has the following permissions\membership:

    - In order to extract DHCP servers data, the user account must be a member of at least 'DHCP Users' group. This group can be either local or domain,
      depending on DHCP infrastructure. If you have multiple AD domains, user account must be added to the 'DHCP Users' group explicitly in each AD domain
      or on each DHCP server.
      More details:
        https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#dhcp-users

    - There are two ways to provide proper permissions to extract DNS servers data (select the one that is prefered by you):
        * User account must be a member of 'DNSAdmins' domain group (exist in each AD domain).
        * User account must have 'Read' permission on a server level in DNS MMC.
This must be done in each DNS server in AD forest.

NOTE: If you decided to use administrative account to run the script, please ensure you're executing it from elevated command prompt.
Otherwise, you may
      receive errors while running operations against DHCP and/or DNS services.

--

PLEASE NOTE - To enable script execution on the server run:

    Set-ExecutionPolicy RemoteSigned

    Or:

    Unblock-File <this-file-name>.ps1


## NOTES

The script will collect 62 metrics.
Each metric is collected by a separate Powershell function.
These functions are included in this script file right after 'param()' keyword.
Functions have the following name format: 'infoblox_<metric-name>'.

Each function in its turn has help section that describes the logic.

Most of DNS-related metrics separated by `int` and `ext` which stand for `internal` and `external` correspondingly.
By the script design, and in order to ensure 
correct calculations later, the following statements are true:

    - DNS zone considered as 'external' if more than 30% of records are pointing to non-local IP addresses (non-RFC-1918). Otherwise it's considered as 'internal'.
 
    - DNS server considered as 'external' if it's hosting at least one 'external' DNS zone. Otherwise it's considered as 'internal'.
 


List of metrics:

    - dhcp_device_count  
    - dhcp_lease_time  
    - dhcp_lps  
    - dhcp_server_count  
    - dhcp_subnet_count  
    - dhcp_vendor  
    - dns_ad_domain_count  
    - dns_caching_forwarders  
    - dns_forward_zone_count  
    - dns_qps  
    - dns_record_count  
    - dns_record_a_count  
    - dns_record_ptr_count  
    - dns_record_aaaa_count  
    - dns_record_txt_count  
    - dns_record_cname_count  
    - dns_record_mx_count  
    - dns_record_ns_count  
    - dns_record_srv_count  
    - dns_reverse_zone_count  
    - dns_zone_dnssec_signed_count  
    - dns_external_record_count  
    - dns_server_count  
    - dns_vendor  
    - gen_active_ip  
    - gen_active_user  
    - gen_site_count  
    - gen_vendor

    - site_entry  
    - site_entry_name  
    - site_entry_source  
    - site_entry_notes  
    - site_entry_dhcp_exclusion_count  
    - site_entry_dhcp_fo_count  
    - site_entry_dhcp_lease_count  
    - site_entry_dhcp_lps  
    - site_entry_dhcp_option_count  
    - site_entry_dhcp_range_count  
    - site_entry_dhcp_range_size  
    - site_entry_dhcp_reservation_count  
    - site_entry_dhcp_service_count  
    - site_entry_dhcp_subnet_count  
    - site_entry_dhcp_subnet_fo_count  
    - site_entry_dns_qps  
    - site_entry_dns_service_count  
    - site_entry_server_count  
    - site_entry_subnet_count  
    - site_entry_user_count  

    - site_all_dhcp_exclusion_count  
    - site_all_dhcp_lease_count  
    - site_all_dhcp_option_count  
    - site_all_dhcp_range_count  
    - site_all_dhcp_range_size  
    - site_all_dhcp_reservation_count  
    - site_all_dhcp_service_count  
    - site_all_dhcp_subnet_count  
    - site_all_dns_record_ad_count  
    - site_all_dns_record_nad_count  
    - site_all_dns_service_count  
    - site_all_dns_zone_ad_count  
    - site_all_dns_zone_nad_count  
    - site_all_site_all_server_count  
    - site_all_subnet_count  


SUPPORTED PARAMETERS

This script supports several parameters, used to control the collection process and output verbosity.
The list below provides a list of parameters
and example of usage.

!!! Important !!!  
Please note that some of the supported parameters are mutually exclusive, meaning, you cannot provide some of them while others are also specified.
In such case, Powershell will print default error message:  
    ```
        Parameter set cannot be resolved using the specified named parameters.
        One or more parameters issued cannot be used together or an insufficient number of parameters were provided.
    ```
    

    * -processOneMetricOnly <metric name>
        Provide this parameter to collect only one metric. The list of valid metrics can be found in this same NOTES section or it will be 
        printed in the error message if you provide unsupported metric name. This parameter is mutually exclusive with 'processDnsMetrics', 
        'processDhcpMetrics' and 'processGenMetrics' parameters.

    * -processDnsMetrics
        Switch-type parameter. Specify it to process DNS_* metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processDhcpMetrics
        Switch-type parameter. Specify it to process DHCP_* metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -processGenMetrics
        Switch-type parameter. Specify it to process GEN_* metrics only. This parameter is mutually exclusive with 'processOneMetricOnly' parameter.

    * -noPrereqCheck
        Switch-type parameter. Specify it to disable pre-requisites check. Might be useful in some rare cases when check function is failing.

    * -noSitesCollection
        Switch-type parameter. Specify it to disable collection SITE_ENTRY_* and SITE_ALL_* metrics.

    * -Verbose
        This is default switch-type parameter of Powershell used to enable verbose output to console. Use this to get more detailed information about
        what is happening during collection process. It's disabled by defaut.


REMOTE SERVERS AVAILABILITY CHECKS

In order to improve performance of the collection script, it has a feature to preliminary check availability of remote servers.
Specifically, it will check:

    * connectivity to the server on port TCP 135 -> required to establish network connection to the servers;
    * ability to query Windows service on the server and its status -> DNS/DHCP services are required to be in the Running state to collect data;
    * ability to make a simple query to the service -> this will check if the current user has required permissions to make requests to services.

These checks will ensure that there are no any issues on collecting required data.
If any of these checks are failing - the server is put into the cache variable and any further attempts to query that server will be skipped.
Corresponding records are written to the log file for further analysis.
Availability of servers is stored in the current Powershell session and 
cleared with every execution of collection script.

For troubleshooting/debug purposes you can check the list of servers in the variable: $global:infoblox_servers


LOCAL CACHING FEATURE

If order to improve performance of the collection script, it has a feature to cache results of remote queries.
This feature is enabled by default
and cannot be disabled.
Cache is stored in current Powershell session and cleared with every execution of collection script.

For troubleshooting/debug purposes you can check the cache in the variable: $global:infoblox_cache

