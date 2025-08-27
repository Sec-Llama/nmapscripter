#!/usr/bin/env bash
# nmap_os_id_recipes.sh
# Field-ready NSE cheat sheet for OS / device identification.
# Usage: replace placeholders like <IP>, <CIDR>, <community>, <DC>, <users.txt>.
# Run with privileges (sudo) for -O, raw sockets, and some UDP probes.


# IMPORTANT !!!! -> Don't use any script you don't know what is doing !
# It can lead to services and systems crashes ! (If you use external non official NSE scripts,\
# you must extra validate it's legit.

################################################################################
# CORE DISCOVERY & OS ID  (Category: discovery,safe,version)
################################################################################

# Generic banner grab across many protocols (optional args: none; safe).
nmap -sV --script=banner <IP>     # Category: discovery | Explanation: grabs banners that often leak OS/stack.

# Strong baseline: service versions + OS fingerprinting + reasons shown (no required args).
nmap -sS -sV -O --reason --version-all <IP>  # Category: discovery,version | Explanation: TCP/IP stack + versions.

# Quick LAN sweep with OS hints (no args required).
nmap -T4 -F -O --reason --version-light <CIDR>  # Category: discovery | Explanation: fast ports + OS guess.

################################################################################
# WINDOWS / SMB / ACTIVE DIRECTORY  (Category: discovery,safe,default)
################################################################################

# Windows OS & domain details over SMB (no args required).
nmap -p445 --script=smb-os-discovery <IP>  # Explanation: Windows version/build, domain/forest, NetBIOS.

# SMB2 capability/time/security (no args required; wildcard runs several scripts).
nmap -p445 --script=smb2-capabilities,smb2-time,smb2-security-mode <IP>  # Explanation: OS age/patch posture hints.

# Enumerate SMB shares/users (no required args; safer on internal nets).
nmap -p445 --script=smb-enum-shares,smb-enum-users <IP>  # Explanation: Environment context; indirect OS clues.

# RPC mapper info (no args required).
nmap -p135 --script=rpcinfo,msrpc-enum <IP>  # Explanation: Windows RPC services → OS flavor/role.

# RDP: NTLM info + encryption profile (no args required).
nmap -p3389 --script=rdp-ntlm-info,rdp-enum-encryption <IP>  # Explanation: Windows family & hardening level.

# WinRM: confirm Windows Server flavor (no args required).
nmap -p5985,5986 --script=winrm-info <IP>  # Explanation: WinRM presence; OS/server role signal.

################################################################################
# LINUX/UNIX/BSD via SSH  (Category: discovery,safe,version)
################################################################################

# SSH host keys (no args required).
nmap -p22 --script=ssh-hostkey <IP>  # Explanation: key types/lengths; sometimes distro defaults.

# SSH algorithm enumeration (no args required).
nmap -p22 --script=ssh2-enum-algos <IP>  # Explanation: cipher/KEX/MAC profile → daemon/OS age.

# SSH auth methods (no args required; posture more than OS).
nmap -p22 --script=ssh-auth-methods <IP>  # Explanation: identifies allowed auth; indirect hints.

################################################################################
# SNMP (NETWORK GEAR / PRINTERS / SERVERS)  (Category: discovery,safe)
################################################################################

# SNMP system description & general info (REQUIRES community string).
# Required: --script-args community=<community>; default port UDP/161.
nmap -sU -p161 --script=snmp-sysdescr,snmp-info <IP> --script-args community=<community>
# Explanation: Often returns exact vendor/OS string (e.g., Cisco IOS, HP iLO).

# SNMP interfaces & processes (same required arg as above).
nmap -sU -p161 --script=snmp-interfaces,snmp-processes <IP> --script-args community=<community>
# Explanation: Confirms device type/role; strengthens OS inference.

################################################################################
# HTTP STACK & FRAMEWORK SIGNALS  (Category: discovery,safe,http)
################################################################################

# Server headers + title (no args required).
nmap -p80,443 --script=http-headers,http-server-header,http-title <IP>
# Explanation: server/banner often leaks OS/distro (IIS/Windows vs Apache on Linux).

# PHP version (no args required; only if PHP exposed in headers).
nmap -p80,443 --script=http-php-version <IP>  # Explanation: maps to platform age.

# NTLM over HTTP (no args required; IIS/AD context).
nmap -p80,443 --script=http-ntlm-info <IP>  # Explanation: Windows edition/domain hints.

# Common config leaks (no args required; use carefully).
nmap -p80,443 --script=http-robots.txt,http-git,http-config-backup <IP>
# Explanation: tech stack clues; sometimes direct OS hints.

################################################################################
# DIRECTORY / IDENTITY SERVICES  (Category: discovery,safe,ldap)
################################################################################

# LDAP RootDSE & naming contexts (no args required for anonymous; add creds if needed).
# Optional: --script-args ldap.username=<u>,ldap.password=<p> if anon bind disabled.
nmap -p389,636 --script=ldap-rootdse,ldap-naming-contexts <IP>
# Explanation: Confirms AD presence, schema → Windows domain inference.

# Kerberos user enum (INTRUSIVE; requires wordlist).
# Required: --script-args userdb=<users.txt>; target usually the DC.
nmap -p88 --script=kerberos-enum-users --script-args userdb=<users.txt> <DC>
# Explanation: Confirms AD; consider legal/ROE before use.

################################################################################
# MAIL & MESSAGING  (Category: discovery,safe,smtp,imap,pop3)
################################################################################

# SMTP banner & commands (no args required).
nmap -p25,465,587 --script=smtp-commands <IP>  # Explanation: daemon banner often leaks OS/distro.

# SMTP user enum (can be intrusive; no required args).
nmap -p25,465,587 --script=smtp-enum-users <IP>

# IMAP capabilities (no args required).
nmap -p143,993 --script=imap-capabilities <IP>  # Explanation: server/version → OS inference.

################################################################################
# DATABASES  (Category: discovery,safe,mysql,pgsql,mongodb,mssql)
################################################################################

# MySQL info (no args required; anonymous handshake).
nmap -p3306 --script=mysql-info <IP>

# PostgreSQL info (no args required).
nmap -p5432 --script=pgsql-info <IP>

# MongoDB info (no args required; only if not fully locked down).
nmap -p27017 --script=mongodb-info <IP>

# Microsoft SQL Server info (no args required).
nmap -p1433 --script=ms-sql-info <IP>  # Explanation: strong Windows signal.

################################################################################
# VIRTUALIZATION / CLOUD EDGES  (Category: discovery,safe,ssl)
################################################################################

# SSL cert details (no args required).
nmap -sV -p443 --script=ssl-cert <IP>  # Explanation: SAN/Issuer may reveal cloud images/providers.

# TLS ALPN (no args required).
nmap -p443 --script=tls-alpn <IP>  # Explanation: CDN/edge fingerprints; indirect OS clues.

################################################################################
# PRINTERS / VOIP / IOT  (Category: discovery,safe,ipp,sip,webdav)
################################################################################

# IPP print services (no args required).
nmap -p631 --script=ipp-discover <IP>  # Explanation: printer model/firmware → OS family.

# WebDAV scan (no args required).
nmap -p80,443 --script=http-webdav-scan <IP>  # Explanation: embedded stacks on appliances.

# SIP methods (no args required; add -sU if UDP).
nmap -p5060,5061 --script=sip-methods <IP>  # Explanation: PBX/VoIP platform leaks.

################################################################################
# BROADCAST / LOCAL DISCOVERY  (Category: discovery,safe,broadcast)
################################################################################

# DHCP discover (no args required; run on local LAN).
nmap --script=broadcast-dhcp-discover
# Explanation: OS install images/relay info; network profile hints.

# mDNS / DNS-SD (no args required).
nmap --script=broadcast-dns-service-discovery

# NetBIOS browser (no args required).
nmap --script=broadcast-netbios-master-browser

# UPnP info (no args required).
nmap --script=broadcast-upnp-info

################################################################################
# TLS/NTLM/SMB FINGERPRINT BOOSTERS  (Category: discovery,safe,ssl,ntlm)
################################################################################

# Enumerate TLS cipher suites (no args required).
nmap -p443 --script=ssl-enum-ciphers <IP>  # Explanation: cipher profile indicates OS/daemon age.

# NTLM info over multiple services (no args required).
nmap -p80,445,3389 --script=ntlm-info <IP>  # Explanation: domain/workgroup, NTLM version.

################################################################################
# DNS & NETBIOS/WINS  (Category: discovery,safe,dns,netbios)
################################################################################

# DNS recursion/NSID (no args required).
nmap -p53 --script=dns-recursion,dns-nsid <IP>  # Explanation: BIND vs Windows DNS traits.

# NetBIOS names (UDP; no args required).
nmap -sU -p137 --script=nbstat <IP>  # Explanation: screams "Windows" with role names.

################################################################################
# OPTIONAL INTERNET-ASSISTED (VERSION→CVE MAPPING)  (Category: vuln,safe)
################################################################################

# vulners: maps discovered versions to known CVEs (no required args; REQUIRES internet).
nmap -sV --script=vulners <IP>  # Explanation: not OS per se, but confirms platform versions.

################################################################################
# “ONE-SHOT” RECIPES (composed scans with multiple scripts)
################################################################################

# Windows-leaning target (no required args).
nmap -sS -sV -O --reason \
  -p135,139,445,3389,5985,5986,80,443 \
  --script=banner,smb-os-discovery,rdp-ntlm-info,rdp-enum-encryption,ntlm-info,http-ntlm-info,smb2-capabilities,smb2-time,smb2-security-mode \
  <IP>

# Linux/Unix-leaning target (no required args).
nmap -sS -sV -O --reason \
  -p22,80,443,111 \
  --script=banner,ssh-hostkey,ssh2-enum-algos,http-headers,http-server-header,rpcinfo \
  <IP>

# Network gear / printers first-pass via SNMP (REQUIRES community).
nmap -sU -p161 --script=snmp-sysdescr,snmp-info <IP> --script-args community=<community>

# LAN service discovery burst (no args required; run on local segment).
nmap --script=broadcast-dns-service-discovery,broadcast-netbios-master-browser,broadcast-upnp-info

################################################################################
# ARGUMENTS QUICK REFERENCE
################################################################################
# --script-args usage pattern:
#   --script-args key=value,key2=value2
# Examples:
#   --script-args community=public                  # REQUIRED by snmp-* scripts unless device uses non-default.
#   --script-args userdb=users.txt                  # REQUIRED by kerberos-enum-users.
#   --script-args ldap.username=alice,ldap.password='P@ssw0rd!'   # OPTIONAL for ldap-* if anon bind disabled.

################################################################################
# PRACTICAL NOTES
################################################################################
# 1) Run as root/Administrator for the best accuracy (-O, raw sockets, UDP).
# 2) OS detection improves with ≥1 open and ≥1 closed port; add --defeat-rst-ratelimit if needed.
# 3) Mix TCP+UDP: many OS hints live on UDP (SNMP/mDNS/NetBIOS).
# 4) Respect ROE: scripts like kerberos-enum-users or smtp-enum-users can be intrusive.
# 5) Correlate: stack (-O) + banners + SMB/SNMP/LDAP beats any single method.
