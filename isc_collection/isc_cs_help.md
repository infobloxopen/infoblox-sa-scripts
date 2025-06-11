# ISC Collection Script (further - ISC CS)
This solution/set of scripts is developed to collect various information about DNS/DHCP infrastructure. Data collected includes basic information about DNS servers, zones, records and statistics; DHCP scopes, leases and statistics.

[!!!] Please review this document to get guide, how to use the solution.

The script is working on per-server basis, meaning the user has to provide server(s) as parameter.

Collection of ISC based configuration is done using options below, depending on scenario users are willing to use during collection process. The choice of the scenario is determined by convenience and permissions that has the end-user.

1. **Local** - Direct collection  
The collection tool is run directly on a DNS/DHCP server.  
With this scenario user run CS on the local server with DNS/DHCP software installed. Script will find and collect configuration files, parse them and prepare output and log files.
2. **SSH** - Remote collection via SSH  
The collection tool is run on a server with SSH access pre-configured to DNS/DHCP servers. All commands are executed via SSH protocol.  
The logic will be the same as _Local_ scenario, but all commands are executed with `ssh <command>`.  
To use this scenario, logged-in user must have configured SSH client software and certificates and SSH agent should be configured on DNS/DHCP servers.
3. **Mount** - Remote collection via mount  
The collection tool is run on a server with root file systems of DNS/DHCP servers mounted locally. File system should be mounted in advance.  
The logic will be the same as _Local_ scenario, but it's assumed that root filesystem of remote DNS/DHCP servers is mounted locally.  
With this approach, some metrics could not be collected (for example - DHCPD server version), because it's impossible to get that information only by reading file system.
4. **Packer** - Exported collection  
A packer tool is first run on a DNS/DHCP servers to package the configuration and zones files in an archive. The archive is copied to a separate server and unpacked. The collection tool is run on a server where the archive is unpacked.  
The logic will be the *similar* to _Local_ scenario, but with some differencies. It's assumed that prior to run the collection tool, the user manually run *packer scripts* on each DNS/DHCP server. These packer scripts will find and collect configuration and DNS zones files (not only configuration of BIND/DHCPD, but also Linux system itself) and prepare them as *.tar.gz archives.  
The user then copy and extract all archives to some server with CS installed and run CS against extracted data.

[!!!] You can combine scenarios per servers, for example: use **Packer** for some servers and **Mount** for some others.

## DNS
Irrelevantly of the usage scenario, the process looks like:

1. Detect location of the `named.conf` file, read it, find all `include` statements (recursively), compile complete configuration and parse to get configuration object.
2. Location of DNS zone files are extracted from the configuration.
3. Some configuration data is collected as metrics.
4. DNS zone files are read to caclulate metrics.

Most of DNS-related metrics separated by `int` and `ext` which stand for `internal` and `external` correspondingly. By the script design, and in order to ensure  correct calculations later, the following statements are true:
- DNS zone considered as 'external' if more than 30% of records are pointing to non-local IP addresses (non-RFC-1918). Otherwise it's considered as 'internal'.
- DNS server considered as 'external' if it's hosting at least one 'external' DNS zone. Otherwise it's considered as 'internal'.

### Metrics
This is a list of collected metrics and their short description.

| Metric                     | Description                                                                                                 |
|----------------------------|-------------------------------------------------------------------------------------------------------------|
| gen_vendor                 | Linux server information.                                                                                   |
| dns_ext_server_count       | Count of processed DNS servers (external).                                                                  |
| dns_ext_forward_zone_count | Number of forward DNS Zones (external).                                                                     |
| dns_ext_reverse_zone_count | Number of reverse DNS Zones (external).                                                                     |
| dns_ext_record_count       | Count of DNS records contained in all zones (external).                                                     |
| dns_ext_qps                | Average queries per second (QPS) (external).                                                                |
| dns_ext_dnssec_used        | Existence of at least one DNSSEC record (NSEC, ...) in any forward zone (external).                         |
| dns_ext_ipv6_used          | Existence of at least one v6 related record (AAAA) record in any zone using a private v6 prefix (external). |
| dns_int_vendor             | BIND9 server version (internal).                                                                            |
| dns_int_server_count       | Count of processed DNS servers (internal).                                                                  |
| dns_int_forward_zone_count | Number of forward DNS Zones (internal).                                                                     |
| dns_int_reverse_zone_count | Number of reverse DNS Zones (internal).                                                                     |
| dns_int_record_count       | Count of DNS records contained in all zones (internal).                                                     |
| dns_int_caching_forwarders | Count of forwarders (internal).                                                                             |
| dns_int_qps                | Average queries per second (QPS) (internal).                                                                |
| dns_int_ipv6_used          | Existence of at least one v6 related record (AAAA) record in any zone using a private v6 prefix (internal). |
| dns_int_dnssec_used        | Existence of at least one DNSSEC record (NSEC, ...) in any forward zone (internal).                         |


### QPS (queries per second) metric
To collect QPS metric, it's required that BIND server is configured to collect statistics. More information: [https://kb.isc.org/docs/aa-00559](https://kb.isc.org/docs/aa-00559).

**Important**  
To get accurate QPS, it's important to update statistics file frequently. The solution will try to update statistics file by running `rndc stats` command, but most likely will fail, because elevated permissions are required to do that. The command failure will be logged as `Error` with two additional `Warning` records. But that particular failure is considered as `Warning`, meaning, this will not halt the execution.
  
QPS can be collected in all scenarios except `packer` (it's impossible to get BIND service uptime in this scenario), but during `mount` solution will not try to update statistics.  
  
In any case, to produce statistics that can be accountable, it's required that the statistics file is refreshed (by `rndc stats`) **AFTER** latest service restart, otherwise, statistics will be 100% untruthful. The solution will check that condition and will discard any QPS calculations if the condition is not met.

## DHCPD
Irrelevantly of the usage scenario, the process looks like:

1. Detect location of the `dhcpd.conf` file, read it, find all `include` statements (recursively), compile complete configuration and parse to get configuration object.
2. Detect location of the `dhcpd.leases` file, read it and parse to get leases object.
3. Extract metrics from `configuration` and `leases`.

### Metrics
This is a list of collected metrics and their short description.

| Metric            | Description                                |
|-------------------|--------------------------------------------|
| gen_vendor        | Linux server information.                  |
| dhcp_vendor       | DHCPD server version.                      |
| dhcp_server_count | Count of processed DNS servers.            |
| dhcp_subnet_count | Number of DHCP subnets / scopes defined.   |
| dhcp_device_count | Count of leases and reservations defined.  |
| dhcp_lease_time   | Average lease time.                        |
| dhcp_lps          | Average number of leases per second (LPS). |

# Pre-requisites
## Software
The following software must be installed on the DNS/DHCP servers:

- `tar` (for **Packer** scenario)
- `awk` (for **Packer** scenario)
- `date` (for **Packer** and **SSH** scenarios)
- `python3` and `python3.xx-venv` (for **Local** scenario, virtual environment is used for isolation, `xx` - version, for example `python3.10-venv`) (may not be required for some Linux systems)
- `sshd` (for **SSH** scenario)
- `ps` (for **SSH** scenario)
- for **Mount** scenario - relevant software

The following software must be installed on the server where CS is run:
- `awk`
- `eval`
- `sha256sum`
- `unzip`
- `curl`
- `ps`
- `python3` (virtual environment is used for isolation)
- `ssh` (for **SSH** scenario)
- for **Mount** scenario - relevant software

## BIND9 Permissions
According to the CS logic, the following files must be readable by the user who run the CS (in case of **SSH** scenario - by the user configured for SSH agent):
- `named.conf` file and all included configuration files
- all DNS zones files that used in configuration
- BIND statistics file, if it's used in the configuration

The CS will also try to run `named -V` command in **SSH**, **Packer** and **Local** scenarios.

## DHCPD Permissions
According to the CS logic, the following files must be readable by the user who run the CS (in case of **SSH** scenario - by the user configured for SSH agent):
- `dhcpd.conf` file and all included configuration files
- `dhcpd.leases` file

The CS will also try to run `dhcpd --version` command in **SSH**, **Packer** and **Local** scenarios.


# Run instructions
## All scenarios
There are two entry-points to the ISC CS solution.
- ./isc_cs_install-script.sh
- ./isc_cs_run-solution.sh

### isc_cs_install-script.sh
This script will download the ISC CS solution, extract it to the `./ib-isc-cs` directory, set execution flags on Bash scripts and create Python virtual environment.
The customer will receive a download URL for this script via e-mail from Sales team representative.

### isc_cs_run-solution.sh
This script will trigger required actions. It requires a parameter to be provided, that will be parsed and various values will be passed to corresponding Python scripts.

Usage:  
`./isc_cs_run-solution.sh --mode|-m <dns|dhcp> --scenario|-s <local|packer|ssh|mount> [--server|-c <servers list>] [--path|-p <path>] ... [<repeat set of parameters>]`

Usage examples:  
`./isc_cs_run-solution.sh --mode dns --scenario ssh --server 10.10.6.30,10.10.6.31 --mode dhcp --scenario local`  
`./isc_cs_run-solution.sh --mode dhcp --scenario local --path /mnt/`  
`./isc_cs_run-solution.sh -m dns -s packer -p /home/user/data/`  
`./isc_cs_run-solution.sh -m dhcp -s local -m dhcp -s ssh -c 10.10.0.1 -m dns -s packer --path ./dns_data/`  

## *Packer* scripts (only for *Packer* scenario)
There are two **Packer** scripts:
- ./packer-script/dns-ib-isc-packer.sh
- ./packer-script/dhcp-ib-isc-packer.sh

To use them, the use copy them to the DNS/DHCP server, run and copy and extract produced archive files to the server where CS is supposed to be run.

All parameters are optional. If not provided, script will try to locate configuration directories and files. Output will be written to the current directory.

### ./packer-script/dns-ib-isc-packer.sh
Usage:  
`./dns-ib-isc-packer.sh [--conf <named.conf path>] [--directory <default directory for BIND configuration>] [--out <output file path>]`

### ./packer-script/dhcp-ib-isc-packer.sh
Usage:  
`./dhcp-ib-isc-packer.sh [--conf <dhcpd.conf path>] [--leases <dhcpd.leases path>] [--out <output file path>]`