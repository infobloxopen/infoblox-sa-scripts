<#
.NOTES
Copyright (C) 2019-2024 Infoblox Inc. All rights reserved.
Version: 1.0.8.0.tags-v1.0.8.47731f2


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


#region ./src/helpers/public/
#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/_IbServer.ps1
class IbServer {
    #region Properties
    [ValidateNotNullOrEmpty()]
    [string]
    $Name

    [Nullable[bool]]
    $Tcp135Avail
    #endregion /Properties


    #region Constructors
    IbServer()
    {
        $this.Tcp135Avail = $null;
    }


    IbServer(
        [string]$name
    )
    {
        $this.Name = $name;
        $this.Tcp135Avail = $null;
    }
    #endregion /Constructors
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/_IbServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/IbDhcpServer.ps1
class IbDhcpServer : IbServer {
    #region Properties
    [string]$Type = "Dhcp"

    [Nullable[bool]]
    $DhcpAvail
    #endregion /Properties

    
    #region Constructors
    IbDhcpServer() {}


    IbDhcpServer(
        [string]$name
    )
    {
        $this.Name = $name;
        $this.DhcpAvail = $null;
    }


    IbDhcpServer(
        [string]$name,
        [bool]$dhcpAvail
    )
    {
        $this.Name = $name;
        $this.DhcpAvail = $dhcpAvail;
    }
    #endregion /Constructors
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/IbDhcpServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/IbDnsServer.ps1
class IbDnsServer : IbServer {
    #region Properties
    [string]$Type = "Dns"

    [Nullable[bool]]
    $DnsAvail
    #endregion /Properties

    
    #region Constructors
    IbDnsServer() {}


    IbDnsServer(
        [string]$name
    )
    {
        $this.Name = $name;
        $this.DnsAvail = $null;
    }


    IbDnsServer(
        [string]$name,
        [bool]$dnsAvail
    )
    {
        $this.Name = $name;
        $this.DnsAvail = $dnsAvail;
    }
    #endregion /Constructors
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@classes/IbDnsServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Export-IbCsv.ps1
function Export-IbCsv {
    [CmdletBinding()]
    param (
        # Array of arrays to export
        [Parameter(Mandatory, ValueFromPipeline)]
        [array[]]
        $array,

        # CSV separator
        [Parameter()]
        [string]
        $separator = ","
    );
    
    
    BEGIN {
        $csvPath = $env:INFOBLOX_SE_CSVPATH;
    }

    
    PROCESS {
        foreach ($item in $array)
        {
            $csvString = "";
            foreach ($subItem in $item)
            {
                $csvString += "$subItem$separator";
            }
            $csvString = $csvString.TrimEnd($separator);

            Add-Content -Path $csvPath -Value $csvString;
        }
    }
    

    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Export-IbCsv.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Get-IbCimExceptionCustomErrorMessage.ps1
function Get-IbCimExceptionCustomErrorMessage {
    [CmdletBinding()]
    param (
        # Value of $_.Exception.MessageId
        [Parameter(Mandatory)]
        [Microsoft.Management.Infrastructure.CimException]
        $exception
    );

    
    BEGIN {}

    
    PROCESS {
        #region Reset variables
        $defaultText,
        $result = $null;
        #endregion /Reset variables

        
        $defaultText = "[Microsoft.Management.Infrastructure.CimException]`n`t"
        $defaultText += "Error code: '$($exception.MessageId)'. ";
        $defaultText += $exception.ErrorData.CimInstanceProperties | ?{$_.name -eq "error_WindowsErrorMessage"} | Select-Object -ExpandProperty Value;
        $defaultText += "`n`t";

        switch ($exception.MessageId)
        {
            "WIN32 4"       { $result = $defaultText + "The issue could be on local computer or remote server. Too many opened files in the system, hence request cannot be completed."; }
            "WIN32 5"       { $result = $defaultText + "Current user does not have permissions to read from the server. This error also may appear if the local computer is unable to reach remote server on port TCP 135."; }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Get-IbCimExceptionCustomErrorMessage.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Get-IbServiceCommandExceptionCustomErrorMessage.ps1
function Get-IbServiceCommandExceptionCustomErrorMessage {
    [CmdletBinding()]
    param (
        # Value of $_.Exception.MessageId
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.ServiceCommandException]
        $exception
    );

    
    BEGIN {}

    
    PROCESS {
        $defaultText = "[Microsoft.PowerShell.Commands.ServiceCommandException]`n`t";

        switch ($exception.HResult)
        {
            -2146233087     { $result = $defaultText + "The issue could also appear if the remote server is turned off or not reachable through network."; }
            Default         { $result = $defaultText + "--- No detailed explanation ---"; }
        }

        
        return $result;
    }

    
    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Get-IbServiceCommandExceptionCustomErrorMessage.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbCsvfilePath.ps1
function Initialize-IbCsvfilePath {
    [CmdletBinding()]
    param (
        # Csv file name
        [Parameter(Mandatory)]
        [string]
        $fileName
    );

    
    $csvPath = "./@output";


    #region Create path to the log file if it doesn't exist
    if (-not $(Test-Path -Path "$csvPath/$fileName"))
    {
        New-Item -Path "$csvPath/$fileName" -Force | Out-Null;
    }
    #endregion /Create path to the log file if it doesn't exist


    Write-Verbose "Setting environment variable 'INFOBLOX_SE_CSVPATH = $csvPath/$fileName' to store CSV file path.";
    Set-Item -Path "env:INFOBLOX_SE_CSVPATH" -Value "$csvPath/$fileName";


    $result = "$csvPath/$fileName";


    return $result;
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbCsvfilePath.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbGlobalVariables.ps1
function Initialize-IbGlobalVariables {
    [CmdletBinding()]
    param (
        
    );

    
    "Initializing global variables." | Write-Verbose;

    $global:infoblox_errors = @();
    $global:infoblox_servers = @();
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbGlobalVariables.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbLogfilePath.ps1
function Initialize-IbLogfilePath {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $fileName,

        [Parameter()]
        [switch]
        $powershellTranscript
    );


    $logPath = "./@logs"


    if (-not $fileName)
    {
        $fileName = "{0}.log" -f $(Get-Date -Format "yyyy-MM-dd_HH-mm-ss");
    }


    if (-not $powershellTranscript)
    {
        #region Create path to the log file if it doesn't exist
        if (-not $(Test-Path -Path "$logPath/$fileName"))
        {
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


    $result = "$logPath/$fileName";


    return $result;
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Initialize-IbLogfilePath.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/New-IbCsMetricsList.ps1
function New-IbCsMetricsList {
    [CmdletBinding()]
    param (
        # Process one metric, if specified
        [Parameter()]
        [ValidateNotNullOrEmpty()]
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
        "Building metrics list to process." | Write-IbLogfile | Write-Verbose;

        
        if ($customMetricName)
        {
            if ($customMetricName -in $defaultMetricsToProcess)
            {
                "Metric '$customMetricName' will be processed only as per 'processOneMetricOnly' parameter." | Write-IbLogfile | Write-Verbose;
                [array]$metricsToProcess = @($customMetricName);
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


            if ($metricsToProcess.Count -eq 0)
            {
                $metricsToProcess = $defaultMetricsToProcess;
            }
        }


        Write-Output -NoEnumerate $metricsToProcess;
    }

    
    END {
        "Finished execution 'Get-IbCsMetricsList'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/New-IbCsMetricsList.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbServer.ps1
function Test-IbServer {
    [CmdletBinding()]
    param (
        # Server address
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $serverName,

        # Server type DNS/DHCP
        [Parameter(Mandatory)]
        [ValidateSet("dhcp", "dns", "default")]
        [string]
        $serverType,

        # Update $global:infoblox_servers variable if checks are implemented in this run
        [Parameter()]
        [switch]
        $skipUpdateEnvironment
    );

    
    BEGIN {
        "Running 'Test-IbServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Testing if the server '$serverName' (type = '$serverType') is available." | Write-IbLogfile | Write-Verbose;


        #region Check if the server already exist in the global array
        switch ($serverType)
        {
            "dns"       { $server = $global:infoblox_servers | ?{$_.GetType().name -eq "IbDnsServer" -and $_.Name -eq $serverName};  }
            "dhcp"      { $server = $global:infoblox_servers | ?{$_.GetType().name -eq "IbDhcpServer" -and $_.Name -eq $serverName}; }
            "default"   { $server = $global:infoblox_servers | ?{$_.GetType().name -eq "IbServer" -and $_.Name -eq $serverName};     }
        }
        #region /Check if the server already exist in the global array


        #region Set result value if it already exists, otherwise - run tests
        $checkPerformed = $false;


        switch ($serverType)
        {
            "dns"
            {
                if ($server)
                {
                    "Server '$($server.Name)' already checked: 'DnsAvail = $($server.DnsAvail)', 'Tcp135Avail = $($server.Tcp135Avail)'." | Write-IbLogfile | Write-Verbose;
                    $result = $server.DnsAvail -and $server.Tcp135Avail;
                }
                else
                {
                    "Server '$serverName' wasn't checked yet. Checking." | Write-IbLogfile | Write-Verbose;

                    $server = [IbDnsServer]::new($serverName);
                    $server.Tcp135Avail = Test-IbWindowsServer -server $serverName;
                    if ($server.Tcp135Avail)
                    {
                        $server.DnsAvail = Test-IbWindowsService -server $serverName -dnsService;
                        $result = $server.Tcp135Avail -and $server.DnsAvail;
                    }
                    else
                    {
                        $result = $false;
                    }

                    $checkPerformed = $true;
                }
            }


            "dhcp"
            {
                if ($server)
                {
                    "Server '$($server.Name)' already checked: 'DhcpAvail = $($server.DhcpAvail)', 'Tcp135Avail = $($server.Tcp135Avail)'." | Write-IbLogfile | Write-Verbose;
                    $result = $server.DhcpAvail -and $server.Tcp135Avail;
                }
                else
                {
                    "Server '$serverName' wasn't checked yet. Checking." | Write-IbLogfile | Write-Verbose;

                    $server = [IbDhcpServer]::new($serverName);
                    $server.Tcp135Avail = Test-IbWindowsServer -server $serverName;
                    if ($server.Tcp135Avail)
                    {
                        $server.DhcpAvail = Test-IbWindowsService -server $serverName -dhcpService;
                        $result = $server.Tcp135Avail -and $server.DhcpAvail;
                    }
                    else
                    {
                        $result = $false;
                    }
                    $checkPerformed = $true;
                }
            }


            "default"
            {
                if ($server)
                {
                    "Server '$($server.Name)' already checked: 'Tcp135Avail = $($server.Tcp135Avail)'." | Write-IbLogfile | Write-Verbose;
                    $result = $server.Tcp135Avail;
                }
                else
                {
                    "Server '$serverName' wasn't checked yet. Checking." | Write-IbLogfile | Write-Verbose;

                    $server = [IbServer]::new($serverName);
                    $server.Tcp135Avail = Test-IbWindowsServer -server $serverName;

                    $result = $server.Tcp135Avail;
                    $checkPerformed = $true;
                }
            }
        }
        #endregion /Set result value if it already exists, otherwise - run tests


        #region Update $global:infoblox_servers variable
        if (-not $skipUpdateEnvironment -and $checkPerformed)
        {
            "Adding check result '$($server | ConvertTo-Json -Compress)' to global variable." | Write-IbLogfile | Write-Verbose;
            $global:infoblox_servers += $server;
        }
        #endregion /Update $global:infoblox_servers variable


        return $result;
    }

    
    END {
        "Finished execution 'Test-IbServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbWindowsServer.ps1
function Test-IbWindowsServer {
    [CmdletBinding()]
    param (
        # Computer name
        [Parameter(Mandatory)]
        [string]
        $server
    );

    
    BEGIN {
        "Running 'Test-IbWindowsServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        "Verifying if '$server' machine is reachable on port TCP 135." | Write-IbLogfile | Write-Verbose;

        
        try
        {
            $resolveDns = Resolve-DnsName -Name $server -Verbose:$false -ErrorAction Stop;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while trying to resolve DNS name '$server'.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            $result = $false;
        }


        if ($resolveDns)
        {
            try
            {
                $originalProgressPreference = $global:ProgressPreference;
                $global:ProgressPreference = "SilentlyContinue";
                $tcpPing = Test-NetConnection -ComputerName $server -Port 135 -WarningAction SilentlyContinue -ErrorAction Stop;
                $global:ProgressPreference = $originalProgressPreference;
            }
            catch
            {
                $global:infoblox_errors += [pscustomobject]@{
                    category = "common";
                    message = $_.Exception.Message;
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
                "Unkown error type. Error while trying to reach '$server' machine on port TCP 135.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
                $result = $false;
            }


            if ($tcpPing.TcpTestSucceeded)
            {
                $result = $true;
                "Machine '$server' is reachable." | Write-IbLogfile | Write-Verbose;
            }
            else
            {
                $result = $false;
                "Machine '$server' is unreachable on port TCP 135." | Write-IbLogfile -severity Warning | Write-Warning;

                $global:infoblox_errors += [pscustomobject]@{
                    category = "common";
                    message = "Machine '$server' is unreachable on port TCP 135.";
                    invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
                };
            }
        }
        else
        {
            "DNS name '$server' could not be resolved." | Write-IbLogfile -severity Warning | Write-Warning;
            $result = $false;

            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = "DNS name '$server' could not be resolved.";
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
        }
        

        return $result;
    }

    
    END {
        "Finished execution 'Test-IbWindowsServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbWindowsServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbWindowsService.ps1
function Test-IbWindowsService {
    [CmdletBinding(DefaultParameterSetName = "ServiceName")]
    param (
        # Computer name
        [Parameter(Mandatory)]
        [string]
        $server,

        # Service name
        [Parameter(Mandatory, ParameterSetName = "ServiceName")]
        [string]
        $serviceName,

        # Check DNS service
        [Parameter(ParameterSetName = "DnsService")]
        [switch]
        $dnsService,

        # Check DHCP service
        [Parameter(ParameterSetName = "DhcpService")]
        [switch]
        $dhcpService
    );

    
    BEGIN {
        "Running 'Test-IbWindowsService'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        if ($dnsService)
        {
            $serviceName = "DNS";
        }
        if ($dhcpService)
        {
            $serviceName = "DHCPServer";
        }


        "Verifying if '$serviceName' Windows service is running on the '$server' machine." | Write-IbLogfile | Write-Verbose;
        
        try
        {
            $serviceStatus = Get-Service -Name $serviceName -ComputerName $server -ErrorAction Stop;

            $result = [pscustomobject]@{
                name = $serviceStatus.name;
                displayName = $serviceStatus.DisplayName;
                status = $serviceStatus.Status;
                startType = $serviceStatus.StartType;
                running = if ($serviceStatus.Status -eq "Running") { $true } else { $false };
            };
        }
        catch [Microsoft.PowerShell.Commands.ServiceCommandException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while getting status of the '$serviceName' Windows service from the '$server' machine.`n`t$_`n`t$(Get-IbServiceCommandExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            $result = $false;
        }
        catch [Microsoft.Management.Infrastructure.CimException]
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error while getting status of the '$serviceName' Windows service from the '$server' machine.`n`t$_`n`t$(Get-IbCimExceptionCustomErrorMessage -exception $_.Exception)`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            $result = $false;
        }
        catch
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = $_.Exception.Message;
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Unkown error type. Error while getting status of the '$serviceName' Windows service from the '$server' machine.`n`t$_`n`t$($_.InvocationInfo.PositionMessage)" | Write-IbLogfile -severity Error | Write-Error;
            $result = $false;
        }


        if ($result -and -not $result.running)
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "common";
                message = "Server '$server' is running, but windows service '$serviceName' is not in the 'Running' state.";
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Server '$server' is running, but windows service '$serviceName' is not in the 'Running' state." | Write-IbLogfile -severity Warning | Write-Warning;
            
            $result = $false;
        }
        elseif ($result -and $result.running)
        {
            $result = $true;
        }


        return $result;
    }

    
    END {
        "Finished execution 'Test-IbWindowsService'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Test-IbWindowsService.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Write-IbLogfile.ps1
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
        [Parameter()]
        [switch]
        $noOutput
    );


    BEGIN {
        $logPath = $env:INFOBLOX_SE_LOGPATH;
    }
 

    PROCESS {
        $datetimeStamp = Get-Date -Format "yyyy-MM-dd HH-mm-ss->fff";
        
        #region Format spaces
        if ($severity.Length -le 7)
        {
            $severityStamp = "[$severity]";
            for ($i = $severity.Length; $i -le 7; $i++)
            {
                $severityStamp = $severityStamp + " ";
            }
        }
        #endregion /Format spaces


        try
        {
            Add-Content -Path $logPath -Encoding UTF8 -Value $($datetimeStamp + "  $severityStamp " + $text) -ErrorAction Stop;
        }
        catch
        {
            Write-Error "Error while trying to write the log file '$logPath'.";
            throw $_;
        }


        if (-not $noOutput)
        {
            return $text;
        }
    }
 

    END {}
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/common/Write-IbLogfile.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpScope.ps1
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
            if (Test-IbServer -serverName $dhcpServer -serverType dhcp)
            {
                [array]$ipv4Scopes = Get-DhcpServerv4Scope -ComputerName $dhcpServer -ErrorAction Stop;
                [array]$ipv6Scopes = Get-DhcpServerv6Scope -ComputerName $dhcpServer -ErrorAction Stop;
            }
            else
            {
                "DHCP server '$dhcpServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpScope.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServer.ps1
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
    }

    
    PROCESS {
        $result = $null;

        
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServerLease.ps1
function Get-IbAdDhcpServerLease {
    [CmdletBinding(DefaultParameterSetName = "ipv4")]
    param (
        # DHCP server
        [Parameter(Mandatory)]
        [string]
        $dhcpServer,

        # Scope ID - for IPv4 scopes
        [Parameter(Mandatory, ParameterSetName = "ipv4")]
        [string]
        $scopeId,

        # Prefix - for IPv4 scopes
        [Parameter(Mandatory, ParameterSetName = "ipv6")]
        [string]
        $scopePrefix,

        # IPv4
        [Parameter(Mandatory, ParameterSetName = "ipv4")]
        [switch]
        $ipv4,

        # IPv6
        [Parameter(Mandatory, ParameterSetName = "ipv6")]
        [switch]
        $ipv6
    );

    
    BEGIN {
        "Running 'Get-IbAdDhcpServerLease'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result,
        $ipv4Leases,
        $ipv6Leases = $null;


        #region IPv4 leases
        if ($ipv4)
        {
            try
            {
                if (Test-IbServer -serverName $dhcpServer -serverType dhcp)
                {
                    [array]$ipv4Leases = Get-DhcpServerv4Lease -ComputerName $dhcpServer -scopeid $scopeId -ErrorAction Stop;
                }
                else
                {
                    "DHCP server '$dhcpServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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
                if (Test-IbServer -serverName $dhcpServer -serverType dhcp)
                {
                    [array]$ipv6Leases = Get-DhcpServerv6Lease -ComputerName $dhcpServer -Prefix $scopePrefix -ErrorAction Stop;
                }
                else
                {
                    "DHCP server '$dhcpServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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
        

        $result = $ipv4Leases + $ipv6Leases;


        return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServerLease'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServerLease.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServerLps.ps1
function Get-IbAdDhcpServerLps {
    [CmdletBinding()]
    param (
        # DHCP server
        [Parameter(ValueFromPipeline, Mandatory)]
        [string]
        $dhcpServer
    );

    
    BEGIN {
        "Running 'Get-IbAdDhcpServerLps'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;
        $ipv4Stats = $null;
        $ipv6Stats = $null;
        $ipv4Lps = $null;
        $ipv6Lps = $null;

        
        "Getting information from '$dhcpServer' DHCP server." | Write-IbLogfile | Write-Verbose;

        #region Getting DHCP server statistics
            #region Getting IPv4 statistics
            try
            {
                "Getting DHCP server IPv4 statistics." | Write-IbLogfile | Write-Verbose;

                if (Test-IbServer -serverName $dhcpServer -serverType dhcp)
                {
                    $ipv4Stats = Get-DhcpServerv4Statistics -ComputerName $dhcpServer -ErrorAction Stop;
                }
                else
                {
                    "DHCP server '$dhcpServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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
                
                if (Test-IbServer -serverName $dhcpServer -serverType dhcp)
                {
                    $ipv6Stats = Get-DhcpServerv6Statistics -ComputerName $dhcpServer -ErrorAction Stop;
                }
                else
                {
                    "DHCP server '$dhcpServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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

            
            if ($ipv4Stats -and $ipv6Stats)
            {
                $uptime = ($(Get-Date) - $ipv4Stats.ServerStartTime).TotalSeconds;
                [decimal]$ipv4Lps = [Math]::Round($ipv4Stats.Acks / $uptime, 2);
                [decimal]$ipv6Lps = [Math]::Round($ipv6Stats.Confirms / $uptime, 2);
                $result = $ipv4Lps + $ipv6Lps

                "Calculated LPS for the server '$dhcpServer = $result'." | Write-IbLogfile | Write-Verbose;
            }
            else
            {
                $result = 0;
            }

            return $result;
    }

    
    END {
        "Finished execution 'Get-IbAdDhcpServerLps'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dhcp/Get-IbAdDhcpServerLps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdDomainController.ps1
function Get-IbAdDomainController {
    [CmdletBinding()]
    param (
        # Domain name
        [Parameter(Mandatory)]
        [string]
        $domain,

        # Filter by Global Catalog role
        [Parameter()]
        [switch]
        $globalCatalog
    );

    
    BEGIN {
        "Running 'Get-IbAdDomainController'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result,
        $params = $null;


        $params = @{
            Server = $domain;
        };


        #region 'globalCatalog' flag was passed
        if ($globalCatalog)
        {
            "'globalCatalog' flag was passed." | Write-IbLogfile | Write-Verbose;
            $params.Service = "GlobalCatalog";
        }
        #endregion /'globalCatalog' flag was passed


        #region Sending request
        try
        {
            if (Test-IbServer -serverName $domain -serverType default)
            {
                [array]$result = Get-ADDomainController @params -Filter "*" -ErrorAction Stop;
                "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
            }
            else
            {
                "AD server '$domain' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdDomainController.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdForest.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdForest.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdServer.ps1
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
        [Parameter(Mandatory)]
        [string]
        $domain,

        # User ADSI queries instead of Powershell
        [Parameter()]
        [switch]
        $useAdsi
    );

    
    BEGIN {
        "Running 'Get-IbAdServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;


        if ($useAdsi)
        {
            # #region Using ADSI queries
            # "'useAdsi' flag was passed. Will be using ADSI queries instead of Powershell." | Write-IbLogfile | Write-Verbose;


            # #region Setting ADSI filter
            # if ($name)
            # {
            #     "Getting server '$name' from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
            #     $query = "(&(&(objectCategory=computer)(objectClass=computer)(name=$name)(operatingSystem=*server*)))";
            # }
            # else
            # {
            #     "Getting servers from '$domain' AD domain." | Write-IbLogfile | Write-Verbose;
            #     $query = "(&(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*)))";
            # }
            # #endregion /Setting ADSI filter


            # if ($domain) { $searchRoot = [adsi]"LDAP://$domain/dc=$($domain.Split(".") -join ",dc=")"; }


            # [array]$result = Invoke-IbAdAdsiQuery -query $query -searchRoot $searchRoot -properties $properties;
            # #endregion /Using ADSI queries
        }
        else
        {
            #region Using Powershell cmdlets
            $params = @{
                Server = $domain;
            };


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
            

            try
            {
                if (Test-IbServer -serverName $domain -serverType default)
                {
                    [array]$result = Get-ADComputer @params -LDAPFilter $ldapFilter -Properties $properties -ErrorAction Stop;
                    "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
                }
                else
                {
                    "AD domain controller '$domain' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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
        

        if ($result)
        {
            Write-Output -NoEnumerate $result;
        }
        else
        {
            return $null;
        }
    }

    
    END {
        "Finished execution 'Get-IbAdServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdSubnet.ps1
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
        "Running 'Get-IbAdSubnet'." | Write-IbLogfile | Write-Verbose;

        $privateIpv4Ranges = "(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)";
        $privateIpv6Ranges = "^f[cd][0-9a-fA-F]{2}:"; # fc00::/7
        $localIpv6Ranges = "^fe[89abAB][0-9a-fA-F]:"; # fe80::/10
    }

    
    PROCESS {
        $result = $null;


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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdSubnet.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdUser.ps1
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

        # Domain to get users from
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $domain
    );

    
    BEGIN {
        "Running 'Get-IbAdUser'. Parameter set used: '$($PSCmdlet.ParameterSetName)'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;


        $params = [hashtable]@{
            Server = $domain;
            Filter = @();
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

            if (Test-IbServer -serverName $domain -serverType default)
            {
                [array]$result = Get-ADUser @params -Properties $properties -ErrorAction Stop;
                "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
            }
            else
            {
                "AD server '$domain' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdUser.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdWorkstation.ps1
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
        [Parameter(Mandatory)]
        [string]
        $domain,

        # User ADSI queries instead of Powershell
        [Parameter()]
        [switch]
        $useAdsi
    );

    
    BEGIN {
        "Running 'Get-IbAdWorkstation'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;


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
            $params = @{
                Server = $domain;
            };


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


            try
            {
                if (Test-IbServer -serverName $domain -serverType default)
                {
                    [array]$result = Get-ADComputer @params -LDAPFilter $ldapFilter -Properties $properties -ErrorAction Stop;
                    "Objects found: $($result.Count)." | Write-IbLogfile | Write-Verbose;
                }
                else
                {
                    "AD server '$domain' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
                }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_common/Get-IbAdWorkstation.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_device_count.ps1
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
                Get-IbAdDhcpServerLease -dhcpServer $_.DhcpServer -scopePrefix $_.Prefix -ipv6;
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_device_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_lease_time.ps1
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

            [decimal]$result = ($ipv4Average + $ipv6Average) / 2;
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_lease_time.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_lps.ps1
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
            [decimal]$result = $dhcpServers | Get-IbAdDhcpServerLps | Measure-Object -Average | Select-Object -ExpandProperty Average;
            [decimal]$result = [Math]::Round($result, 2);
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_lps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_server_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_subnet_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_subnet_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_vendor.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dhcp_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_dnssec_used.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_dnssec_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_forward_zone_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_forward_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_ipv6_used.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_ipv6_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_qps.ps1
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
        [decimal]$result = $domains `
            | Get-IbAdDnsServer | Select-Object -Unique `
            | Select-IbAdDnsServer -external `
            | Get-IbAdDnsZone -external | Select-Object -Unique DnsServer -ExpandProperty DnsServer `
            | Get-IbAdDnsServerQps `
            | Measure-Object -Sum | Select-Object -ExpandProperty Sum;
            
        [decimal]$result = [Math]::Round($result, 2);

        return @("dns_ext_qps", $result);
    }
    

    END {
        "[***] Finished collection 'dns_ext_qps'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_qps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_record_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_record_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_reverse_zone_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_reverse_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_server_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_ext_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_ad_domain_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_ad_domain_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_caching_forwarders.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_caching_forwarders.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_dnssec_used.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_dnssec_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_forward_zone_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_forward_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_ipv6_used.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_ipv6_used.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_qps.ps1
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
        [decimal]$result = $domains `
            | Get-IbAdDnsServer | Select-Object -Unique `
            | Select-IbAdDnsServer -internal `
            | Get-IbAdDnsZone -internal | Select-Object -Unique DnsServer -ExpandProperty DnsServer `
            | Get-IbAdDnsServerQps `
            | Measure-Object -Sum | Select-Object -ExpandProperty Sum;
            
        [decimal]$result = [Math]::Round($result, 2);

        return @("dns_int_qps", $result);
    }


    END {
        "[***] Finished collection 'dns_int_qps'." | Write-IbLogfile | Write-Verbose;
        " " | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_qps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_record_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_record_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_reverse_zone_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_reverse_zone_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_server_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_server_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_vendor.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/dns_int_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_active_ip.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_active_ip.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_active_user.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_active_user.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_site_count.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_site_count.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_vendor.ps1
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/@infoblox_collection/gen_vendor.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsForwarderConfiguration.ps1
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
        $result,
        $generalForwardingConfig,
        $forwarderZones = $null;


        "Getting the forwarding configuration for the '$dnsServer' DNS server." | Write-IbLogfile | Write-Verbose;

        #region Get general forwarding configuration
        try
        {
            if (Test-IbServer -serverName $dnsServer -serverType dns)
            {
                $generalForwardingConfig = Get-DnsServerForwarder -ComputerName $dnsServer -ErrorAction Stop;
            }
            else
            {
                "DNS server '$dnsServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
            if (Test-IbServer -serverName $dnsServer -serverType dns)
            {
                [array]$forwarderZones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop | ?{$_.ZoneType -eq "Forwarder"};
            }
            else
            {
                "DNS server '$dnsServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsForwarderConfiguration.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsRecord.ps1
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
        "Running 'Get-IbAdDnsRecord'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;


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
            if (Test-IbServer -serverName $dnsServer -serverType dns)
            {
                [array]$result = $params | %{
                    Get-DnsServerResourceRecord @_ -ErrorAction Stop;
                };
            }
            else
            {
                "DNS server '$dnsServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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


        # If $result contains a lot of records, Write-Output will hang
        if ($result.count -eq 1)
        {
            Write-Output -NoEnumerate $result;
        }
        else
        {
            return $result;
        }
    }

    
    END {
        "Finished execution 'Get-IbAdDnsRecord'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsRecord.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsServer.ps1
function Get-IbAdDnsServer {
    [CmdletBinding()]
    param (
        # AD domain name (FQDN)
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $domain
    );

    
    BEGIN {
        "Running 'Get-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result = $null;


        "Getting DNS servers in the '$domain' AD domain." | Write-IbLogfile | Write-Verbose;

        #region Get list of DNS servers
        [array]$result = Get-IbAdDnsRecord -dnsServer $domain -zoneName $domain -type Ns `
            | ?{$_.HostName -eq "@"} `
            | %{$_.RecordData.NameServer.TrimEnd(".")};
        #endregion /Get list of DNS servers

        
        if ($result)
        {
            Write-Output -NoEnumerate $result;
        }
        else
        {
            return $null;
        }
    }

    
    END {
        "Finished execution 'Get-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsServer.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsServerQps.ps1
function Get-IbAdDnsServerQps {
    [CmdletBinding()]
    param (
        # DNS server FQDN
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $dnsServer
    );

    
    BEGIN {
        "Running 'Get-IbAdDnsServerQps'." | Write-IbLogfile | Write-Verbose;
    }

    
    PROCESS {
        $result,
        $statistics,
        $qps = $null;


        "Getting QPS (queries per second) metric from '$dnsServer' DNS server." | Write-IbLogfile | Write-Verbose;

        #region Get statistics object
        try
        {
            if (Test-IbServer -serverName $dnsServer -serverType dns)
            {
                $statistics = Get-DnsServerStatistics -ComputerName $dnsServer -ErrorAction Stop;
            }
            else
            {
                "DNS server '$dnsServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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


        if ($statistics.Query2Statistics.TotalQueries `
            -and $statistics.TimeStatistics.TimeElapsedSinceServerStart.TotalSeconds `
            -and $statistics.TimeStatistics.TimeElapsedSinceServerStart.TotalSeconds -ne 0)
        {
            [decimal]$qps = [Math]::Round($statistics.Query2Statistics.TotalQueries / $statistics.TimeStatistics.TimeElapsedSinceServerStart.TotalSeconds, 2);
        }
        elseif (-not $statistics)
        {
            $qps = 0;
        }
        else
        {
            $global:infoblox_errors += [pscustomobject]@{
                category = "ad_dns";
                message = "Error in calculations. Statistics data received from the server may be corrupted.";
                invokationPath = (Get-PSCallStack)[-1 .. -((Get-PSCallStack).length)].command -join " -> ";
            };
            "Error in calculations. Statistics data received from the server may be corrupted." | Write-IbLogfile -severity Error | Write-Error;
            $qps = 0;
        }


        return $qps;
    }

    
    END {
        "Finished execution 'Get-IbAdDnsServerQps'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsServerQps.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsZone.ps1
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
        [Parameter()][decimal]$extIntRatio = 0.3,

        # Ratio to identify if the zone contain IPv6 records
        [Parameter()][decimal]$ipv6Ratio = 0.3,

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
        $result,
        $zones,
        $records,
        $zoneRangePrefix = $null;


        #region Get all zones
        try
        {
            "Getting '$($PSCmdlet.ParameterSetName)' zones from the DNS server '$dnsServer'." | Write-IbLogfile | Write-Verbose;
            if (Test-IbServer -serverName $dnsServer -serverType dns)
            {
                $zones = Get-DnsServerZone -ComputerName $dnsServer -ErrorAction Stop | ?{-not $_.IsAutoCreated -and $_.ZoneType -ne "Forwarder" -and $_.ZoneName -ne "TrustAnchors"};
            }
            else
            {
                "DNS server '$dnsServer' is detected as not available. Skipping." | Write-IbLogfile -severity Warning | Write-Warning;
            }
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
            "Classifying '$($zone.ZoneName)' zone." | Write-IbLogfile | Write-Verbose;


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
        
        
        # If $result contains a lot of records, Write-Output will hang
        if ($result.count -eq 1)
        {
            Write-Output -NoEnumerate $result;
        }
        else
        {
            return $result;
        }
    }

    
    END {
        "Finished execution 'Get-IbAdDnsZone'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Get-IbAdDnsZone.ps1


#region /home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Select-IbAdDnsServer.ps1
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
        #region Reset variables
        $externalZones = $null;
        #endregion /Reset variables


        "Checking if DNS server '$dnsServer' is 'internal' or 'external'." | Write-IbLogfile | Write-Verbose;

        
        $externalZones = $dnsServer | Get-IbAdDnsZone -external;


        # Server can be either 'external' or 'internal', it cannot be 'external' and 'internal' at the same time.
        # If at least one 'external' zone exist on the server - the whole server is considered as 'external'. Otherwise - it will be 'internal'.
        # If we've got at least one 'external' zone - return the server
        if ($PSCmdlet.ParameterSetName -eq "External")
        {
            if ($externalZones)
            {
                return $dnsServer;
            }
        }
        # If we haven't got any 'external' zones - return the server
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
    }

    
    END {
        "Finished execution 'Select-IbAdDnsServer'." | Write-IbLogfile | Write-Verbose;
    }
}
#endregion //home/runner/work/infoblox-ms-collection/infoblox-ms-collection/src/helpers/public/ad_dns/Select-IbAdDnsServer.ps1
#endregion /./src/helpers/public/


#region ./_templates/common--main--body.ps1
$version = "1.0.8.0.tags-v1.0.8.47731f2";


$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss";
$result = @();


Initialize-IbGlobalVariables;
Initialize-IbLogfilePath -fileName "$dateTime.log" | Out-Null;
Initialize-IbLogfilePath -fileName "$dateTime.pwsh.log" -powershellTranscript | Out-Null;
Initialize-IbCsvfilePath -fileName "$dateTime.csv";
Write-Output " ";
"Script version: $version" | Write-IbLogfile | Write-Output;
Write-Output "";


Start-Transcript -Path $env:INFOBLOX_PWSH_TRANSCRIPT_PATH;


#region Define metrics to collect
$params = @{
    processDnsMetrics = $processDnsMetrics;
    processDhcpMetrics = $processDhcpMetrics;
    processGenMetrics = $processGenMetrics;
};

if ($processOneMetricOnly)
{
    $params.customMetricName = $processOneMetricOnly;
}

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
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAMLYos4BjhWnMZ
# k+pkNZ/8T/+heScCwIn7Nk7gWXY6J6CCDZgwggawMIIEmKADAgECAhAIrUCyYNKc
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
# 3rcxghnqMIIZ5gIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEA4xh5LA5myIPSfcfOZGLB4wDQYJ
# YIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgasJFaLfcGxFF78eRMOy1zlQSUEeJ42gRR3jDexz6fn0wDQYJKoZI
# hvcNAQEBBQAEggGAZts1lqu13Z0+29Or6ydGuQEIraLidp60A/VTfRD5udMqf0UU
# YRH9BTnofa1njg0VIQ+op9mgxmwgvNCIvZNFE9hcXNkezsVub5kgkq0XjCjshRDl
# vxV0SXh85cPT8WeldrRr+i/V35AQFSlUFzjFd6SG09+Qcj4PQ6oSYrWEejP17BXd
# GcrLx8gstrrq6hgxZWbv7ZNdvgHsgWVvDSeCL0y0jW4lmrkKWdlcKQ7hC4yrLOOC
# FSU/YdPLNAJzmQKlsofe1LY8RBfraJ3vfGDRhzQKzHGetqszPueLiVpBgfFSp/uw
# //kB6m28wB3xDwpt/ZORM9sFcW5IQBiOF18pV2KzNNxclfleGSl5kgFo1w1MKduc
# jz21VZuNuZGw556jvL7/kY33j5YfscupI2CbZlUa0C9cLDP2m9G5e7iVfN3RsthZ
# wBNASXijvrDD96VvJ9TCMVxW4AzyIZ3nhefKUt1z+rD0S8OYSzPE/jErY92RSU1y
# qcw41lxDtOIb7zw1oYIXQDCCFzwGCisGAQQBgjcDAwExghcsMIIXKAYJKoZIhvcN
# AQcCoIIXGTCCFxUCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBp
# BGcwZQIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIJsupacxt66HfmMj
# qdQNjci7NahtHbDj/+I9djlodaEmAhEA31hlXzIF/7sXMKf3FFHltxgPMjAyNDA4
# MjIxNTMzMDJaoIITCTCCBsIwggSqoAMCAQICEAVEr/OUnQg5pr/bP1/lYRYwDQYJ
# KoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQTAeFw0yMzA3MTQwMDAwMDBaFw0zNDEwMTMyMzU5NTla
# MEgxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UE
# AxMXRGlnaUNlcnQgVGltZXN0YW1wIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQCjU0WHHYOOW6w+VLMj4M+f1+XS512hDgncL0ijl3o7Kpxn3GIV
# WMGpkxGnzaqyat0QKYoeYmNp01icNXG/OpfrlFCPHCDqx5o7L5Zm42nnaf5bw9Yr
# IBzBl5S0pVCB8s/LB6YwaMqDQtr8fwkklKSCGtpqutg7yl3eGRiF+0XqDWFsnf5x
# XsQGmjzwxS55DxtmUuPI1j5f2kPThPXQx/ZILV5FdZZ1/t0QoRuDwbjmUpW1R9d4
# KTlr4HhZl+NEK0rVlc7vCBfqgmRN/yPjyobutKQhZHDr1eWg2mOzLukF7qr2JPUd
# vJscsrdf3/Dudn0xmWVHVZ1KJC+sK5e+n+T9e3M+Mu5SNPvUu+vUoCw0m+PebmQZ
# BzcBkQ8ctVHNqkxmg4hoYru8QRt4GW3k2Q/gWEH72LEs4VGvtK0VBhTqYggT02ke
# fGRNnQ/fztFejKqrUBXJs8q818Q7aESjpTtC/XN97t0K/3k0EH6mXApYTAA+hWl1
# x4Nk1nXNjxJ2VqUk+tfEayG66B80mC866msBsPf7Kobse1I4qZgJoXGybHGvPrhv
# ltXhEBP+YUcKjP7wtsfVx95sJPC/QoLKoHE9nJKTBLRpcCcNT7e1NtHJXwikcKPs
# CvERLmTgyyIryvEoEyFJUX4GZtM7vvrrkTjYUQfKlLfiUKHzOtOKg8tAewIDAQAB
# o4IBizCCAYcwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MB8GA1UdIwQYMBaAFLoW2W1NhS9zKXaaL3WMaiCPnshvMB0GA1UdDgQWBBSltu8T
# 5+/N0GSh1VapZTGj3tXjSTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0
# YW1waW5nQ0EuY3JsMIGQBggrBgEFBQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGlt
# ZVN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCBGtbeoKm1mBe8cI1P
# ijxonNgl/8ss5M3qXSKS7IwiAqm4z4Co2efjxe0mgopxLxjdTrbebNfhYJwr7e09
# SI64a7p8Xb3CYTdoSXej65CqEtcnhfOOHpLawkA4n13IoC4leCWdKgV6hCmYtld5
# j9smViuw86e9NwzYmHZPVrlSwradOKmB521BXIxp0bkrxMZ7z5z6eOKTGnaiaXXT
# UOREEr4gDZ6pRND45Ul3CFohxbTPmJUaVLq5vMFpGbrPFvKDNzRusEEm3d5al08z
# jdSNd311RaGlWCZqA0Xe2VC1UIyvVr1MxeFGxSjTredDAHDezJieGYkD6tSRN+9N
# UvPJYCHEVkft2hFLjDLDiOZY4rbbPvlfsELWj+MXkdGqwFXjhr+sJyxB0JozSqg2
# 1Llyln6XeThIX8rC3D0y33XWNmdaifj2p8flTzU8AL2+nCpseQHc2kTmOt44Owde
# OVj0fHMxVaCAEcsUDH6uvP6k63llqmjWIso765qCNVcoFstp8jKastLYOrixRoZr
# uhf9xHdsFWyuq69zOuhJRrfVf8y2OMDY7Bz1tqG4QyzfTkx9HmhwwHcK1ALgXGC7
# KP845VJa1qwXIiNO9OzTF/tQa/8Hdx9xl0RBybhG02wyfFgvZ0dl5Rtztpn5aywG
# Ru9BHvDwX+Db2a2QgESvgBBBijCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYq
# XlswDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIz
# NTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTsw
# OQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVT
# dGFtcGluZyBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJ
# s8E9cklRVcclA8TykTepl1Gh1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJ
# C3+dH54PMx9QEwsmc5Zt+FeoAn39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+
# QtxnjupRPfDWVtTnKC3r07G1decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3
# eZ9drMvohGS0UvJ2R/dhgxndX7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbF
# Hc02DVzV5huowWR0QKfAcsW6Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71
# h6aPTnYVVSZwmCZ/oBpHIEPjQ2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseS
# v6De4z6ic/rnH1pslPJSlRErWHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj
# 1QPgv/CiPMpC3BhIfxQ0z9JMq++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2L
# INIsVzV5K6jzRWC8I41Y99xh3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJ
# jAw7W4oiqMEmCPkUEBIDfV8ju2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAO
# hFTuzuldyF4wEr1GnrXTdrnSDmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88w
# U86/GPvHUF3iSyn7cIoNqilp/GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZv
# xFBMYh0MCIKoFr2pVs8Vc40BIiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+R
# Zp4snuCKrOX9jLxkJodskr2dfNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM
# 8HKjI/rAJ4JErpknG6skHibBt94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/E
# x8HBanHZxhOACcS2n82HhyS7T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd
# /yVjmScsPT9rp/Fmw0HNT7ZAmyEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFP
# vT87eK1MrfvElXvtCl8zOYdBeHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHics
# JttvFXseGYs2uJPU5vIXmVnKcPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2V
# Qbc61RWYMbRiCQ8KvYHZE/6/pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ
# 8GV2QqYphwlHK+Z/GqSFD/yYlvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr
# 9u3WfPwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEB
# DAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQg
# SUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJ
# BgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5k
# aWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPs
# wqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLk
# X9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDtt
# ceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hI
# qGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2
# scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm
# 2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaH
# iZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3r
# M9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJ
# B+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRES
# W+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kxfgom
# mfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKG
# N2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJv
# b3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUd
# IAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGH
# LOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7Q
# Kt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajw
# vy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQ
# Pfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFq
# I2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIB
# ATB3MGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0ECEAVEr/OUnQg5pr/bP1/lYRYwDQYJYIZIAWUDBAIBBQCggdEwGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDA4MjIx
# NTMzMDJaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFGbwKzLCwskPgl3OqorJxk8Z
# nM9AMC8GCSqGSIb3DQEJBDEiBCA0OYF3LyjXxU5lvyRvB3DPs4kdGY43w5TT2DDG
# Gg3vgTA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCDS9uRt7XQizNHUQFdoQTZvgora
# VZquMxavTRqa1Ax4KDANBgkqhkiG9w0BAQEFAASCAgCPyMJiO0l2QiBkcKRQ98vk
# 7tYaWlH/7cd3a3bOSOPo6mRneClkw7cj1lStmh2y6OqlwQKGHK8f3SKicC7hA9C1
# O+Jur5p5+m+enay1Qz2C7Zo3PoEl8mXQMMOW+7uogia08zwklTY05IpYR+KOXQEt
# v2bYi4mYn1FVfDiBoR9Gyk/wCIe111g9unxO4n1ls3BmXsXIQTA33GFEScKC9NVX
# 3L9/MljCWZFT4XuOMoZxKix/hTGt06R4s5A6sqLYWf9+JL9iJxAbHJ1mVWG82Flq
# NB1a8d8CO0d3tKlpFP876tuE+Y5LbEOiUrwxHG9Z+s1iGNIQ4bQVR7kPDg7x2PLi
# g+nQ0JWf2L8uxbAG3vGt/Dj8g22JB4WLMco/wDxTb/REX186sxHiJk1lzC2o4IWk
# FtQxcd95GDeZr1mQL0hBKnk+D+UtrixYjUX8Lslj9DNdpMPjvigshvPvjOC/NXCT
# 15eUC5wgWRh1UoJ9NWRsiSuIYMsZkSbbIpVQzNyM0q50qNpoJzwzqctXuXfKB3tf
# aZGnacV+oxj3j1lmMBoQEGDsonOvTnsHZTFnf/WwvSfTOzHcmtip57v7Y6p3vfvT
# hrKX9EejLtxicwRpxDFVmyCdal+khztgJM/PuOzof7HAhrlIMsoiQWebqdviouok
# qSzQA1vDSPRas3PQ/JR10A==
# SIG # End signature block
