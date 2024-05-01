# Infoblox Sales Acceleration Scripts

About
=====
Infoblox sales acceleration scripts are a set of scripts that can be used to automate the sales process. The scripts include the following:
- `survey`:  User survey for prospects/customers for data collection process. The survey form can be used to collect information about the prospect/customer's environment, requirements, and preferences.
- `collections`: A set of collection scripts to gather acurate and up-to-date information for Infoblox Solutions/Proposal. The scripts include the following:
  - `msad-cs`: Gathers up-to-date DDI information from a customers/prospects Microsoft Active Directory environment.

Requirements
============
- PowerShell 5.1 and above
- Windows 10 and above

MS AD Collection Overview
===========================
The `msad-cs` collection collects data DNS/DHCP/IPAM data from a Microsoft Active Directory environment. The collection includes MS AD topology, computers, users accounts, DNS zones, DHCP scopes, and IPAM data.

How to use the `msad-cs` collection
------------------------------------
To run this tool perform the following steps:
1. Log on to a Windows machine where you plan to run the script. 
2. Ensure that all prerequisites are met to run the script. 
3. Copy script to a writable directory where the output files are to be stored and CD to it using Powershell console. 
4. Run the script. 
5. Examine output for errors (in the same console window or in the log file in the ./@logs/ directory). 
6. Logs will be created in the ./@logs/ directory, output file - in the ./@output/ directory. 
7. Zip and send all output and log files.

Prerequisites
-------------
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
