#LDAPDomainDump
Active Directory information dumper via LDAP

##Introduction
In an Active Directory domain, a lot of interesting information can be retrieved via LDAP by any authenticated user (or machine).
This makes LDAP an interesting protocol for gathering information in the recon phase of a pentest of an internal network.
A problem is that data from LDAP often is not available in an easy to read format.

ldapdomaindump is a tool which aims to solve this problem, by collecting and parsing information available via LDAP and outputting it in a human readable HTML format, as well as machine readable json and csv/tsv/greppable files.

The tool was designed with the following goals in mind:
- Easy overview of all users/groups/computers/policies in the domain
- Authentication both via username and password, as with NTLM hashes (requires ldap3 >=1.3.1)
- Possibility to run the tool with an existing authenticated connection to an LDAP service, allowing for integration with relaying tools such as impackets ntlmrelayx

The tool outputs several files containing an overview of objects in the domain:
- *domain_groups*: List of groups in the domain
- *domain_users*: List of users in the domain
- *domain_computers*: List of computer accounts in the domain
- *domain_policy*: Domain policy such as password requirements and lockout policy

As well as two grouped files:
- *domain_users_by_group*: Domain users per group they are member of
- *domain_computers_by_os*: Domain computers sorted by Operating System

##Dependencies and installation
Requires [ldap3](https://github.com/cannatag/ldap3) and [dnspython](https://github.com/rthalley/dnspython)

Both can be installed with `pip install ldap3 dnspython`

The ldapdomaindump package can be installed with `python setup.py install` from the git source, or for the latest release with `pip install ldapdomaindump`.

##Usage
There are 3 ways to use the tool:
- With just the source, run `python ldapdomaindump.py`
- After installing, by running `python -m ldapdomaindump`
- After installing, by running `ldapdomaindump`

Help can be obtained with the -h switch:
```
usage: ldapdomaindump.py [-h] [-u USERNAME] [-p PASSWORD] [-o DIRECTORY]
                         [--no-html] [--no-json] [--no-grep] [-d DELIMITER]
                         [-r] [-n DNS_SERVER]
                         HOSTNAME

Domain information dumper via LDAP. Dumps users/computers/groups and
OS/membership information to HTML/JSON/greppable output.

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        connect to

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication, leave empty for
                        anonymous authentication
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified

Output options:
  -o DIRECTORY, --outdir DIRECTORY
                        Directory in which the dump will be saved (default:
                        current)
  --no-html             Disable HTML output
  --no-json             Disable JSON output
  --no-grep             Disable Greppable output
  -d DELIMITER, --delimiter DELIMITER
                        Field delimiter for greppable output (default: tab)

Misc options:
  -r, --resolve         Resolve computer hostnames (might take a while and
                        cause high traffic on large networks)
  -n DNS_SERVER, --dns-server DNS_SERVER
                        Use custom DNS resolver instead of system DNS (try a
                        domain controller IP)
```

##Options
At the moment, the options of the tool are limited. Most options are self-explanatory, just an important one is the *-r* option, which decides if a computers DNSHostName attribute should be resolved to an IPv4 address. 
While this can be very useful, the DNSHostName attribute is not automatically updated. When the AD Domain uses subdomains for computer hostnames, the DNSHostName will often be incorrect and will not resolve. Also keep in mind that resolving every hostname in the domain might cause a high load on the domain controller.

##License
MIT
