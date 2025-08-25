# Nmap NSE OS Identification Cheat Sheet (Args-Verified)

This is a **field-ready NSE cheat sheet** for identifying OS & device types.  
Below is an **Arguments Matrix** that clarifies which scripts **require** arguments and which accept **helpful optional** arguments for better results.

---

## ⚙️ How to pass script args
```bash
nmap <other options> --script=<script1,script2,...> --script-args key=value,key2=value2 <target>
# You can also pass per-script args with a table-style syntax:
nmap --script "snmp-sysdescr,snmp-info" --script-args "snmpcommunity=public"
```

> Some scripts support both global-style keys and namespaced keys (e.g., `ldap.username`).  
> Always prefer the key names shown **exactly** as below.

---

## 🧭 Arguments Matrix (required vs optional & helpful)

| Script(s) | Requires Args? | Helpful/Optional Args | Notes (what the args do / when to use) |
|---|---|---|---|
| `banner` | No | — | Generic banner grab. No args needed. |
| `smb-os-discovery` | No | `smbusername`, `smbpassword`, `smbdomain` | Anonymous often works, but creds can yield more robust/consistent info in hardened AD environments. |
| `smb2-capabilities`, `smb2-time`, `smb2-security-mode` | No | `smbusername`, `smbpassword`, `smbdomain` | Optional creds reduce access-denied noise on locked-down hosts. |
| `smb-enum-shares`, `smb-enum-users` | No | `smbusername`, `smbpassword`, `smbdomain` | Anonymous may be limited; credentials greatly improve enumeration. |
| `rpcinfo`, `msrpc-enum` | No | — | Queries RPC mapper. No args typically required. |
| `rdp-ntlm-info`, `rdp-enum-encryption` | No | — | Pulls NTLM info & encryption profile over 3389. |
| `winrm-info` | No | `auth.user`, `auth.pass` | Often returns basics unauthenticated; credentials can expose more detail (if policy permits). |
| `ssh-hostkey` | No | `ssh_max_probes=<n>`, `ssh_hostkey=md5,sha256` | Defaults are fine; tweaking probes can speed up/avoid timeouts on flaky links. |
| `ssh2-enum-algos` | No | — | Lists SSH KEX/ciphers/MACs; no args needed. |
| `ssh-auth-methods` | No | `ssh.user=<name>` | Set a username to check allowed auth methods for that user (informative posture signal). |
| `snmp-sysdescr`, `snmp-info` | **Yes (usually)** | `snmpcommunity=<string>`, `snmpversion=1|2c|3`, `snmpseclevel=noAuthNoPriv|authNoPriv|authPriv`, `snmpauthuser=<u>`, `snmpauthpass=<p>`, `snmpauthproto=MD5|SHA`, `snmpprivpass=<p>`, `snmpprivproto=DES|AES` | **Most deployments disable anonymous/public.** Provide correct community for v1/v2c or full v3 creds for best results. |
| `snmp-interfaces`, `snmp-processes` | **Yes (usually)** | Same as above | Same requirements as other SNMP scripts. |
| `http-headers`, `http-server-header`, `http-title` | No | `http.useragent=<UA>`, `path=/custom` | Useful when sites behave differently by UA or path. |
| `http-php-version` | No | `path=/index.php` | If PHP banners aren’t on `/`, specify a known PHP-handled path. |
| `http-ntlm-info` | No | `ntlm.domain=<d>`, `ntlm.workstation=<w>` | Not required; setting expected domain/workstation can improve negotiation signals. |
| `http-robots.txt`, `http-git`, `http-config-backup` | No | `http-git.path=/`, `http-config-backup.root=/var/www/html` | Paths help if repos/backups live in non-default locations. |
| `ldap-rootdse`, `ldap-naming-contexts` | No (if anon bind allowed) | `ldap.username=<u>,ldap.password=<p>`, `ldap.base=<DN>`, `ldap.port=389|636` | If anonymous bind is disabled (common), provide creds; set base DN explicitly if discovery fails. |
| `kerberos-enum-users` | **Yes** | `userdb=<file>`, `domain=<REALM>`, `kdc=<IP/FQDN>`, `passive=yes|no` | **Requires a user list.** Setting `domain`/`kdc` makes results deterministic. Intrusive; respect ROE. |
| `smtp-commands` | No | `smtp.domain=<example.com>` | Some MTAs tailor responses by EHLO domain. |
| `smtp-enum-users` | No | `smtp-enum-users.methods=EXPN,VRFY,RCPT`, `smtp.domain=<example.com>` | Intrusive; specifying methods/domain improves coverage. |
| `imap-capabilities` | No | — | No args needed. |
| `mysql-info` | No | `mysqluser`, `mysqlpass` | Works unauth for handshake/version; creds reveal more server metadata if allowed. |
| `pgsql-info` | No | `pgsql.user`, `pgsql.pass` | Similar to MySQL; optional creds deepen results. |
| `mongodb-info` | No | — | Older/unauth instances respond; locked-down modern ones may not. |
| `ms-sql-info` | No | `mssql.username`, `mssql.password`, `mssql.instance-name`, `mssql.instance-port` | Unaudited info may be limited; instance parameters help in multi-instance deployments. |
| `ssl-cert` | No | `ssl-cert.showcerts=true` | Show full cert chain if needed. |
| `tls-alpn` | No | — | No args needed. |
| `ipp-discover` | No | — | No args needed. |
| `http-webdav-scan` | No | `path=/webdav/` | If DAV is not at `/`, set a hint path. |
| `sip-methods` | No | `sip.methods=INVITE,OPTIONS,REGISTER`, `sip.user=<u>`, `sip.transport=udp|tcp|tls` | Tuning transport and methods improves coverage (SIP often runs over UDP 5060). |
| `broadcast-dhcp-discover` | No | `newtargets` | `newtargets` adds discovered hosts to the scan queue automatically. |
| `broadcast-dns-service-discovery` | No | `newtargets` | Same. |
| `broadcast-netbios-master-browser` | No | `newtargets` | Same. |
| `broadcast-upnp-info` | No | `newtargets` | Same. |
| `ssl-enum-ciphers` | No | `ssl-enum-ciphers.maxlist=<n>`, `ssl-enum-ciphers.show_tlsv1=false` | Trim output or limit protocol versions for speed/clarity. |
| `ntlm-info` | No | `ntlm.domain=<d>`, `ntlm.workstation=<w>` | Helpful for more consistent NTLM negotiation metadata. |
| `dns-recursion`, `dns-nsid` | No | `dns-nsid.id=<hex>` | Custom NSID payload if you need to test response behavior. |
| `nbstat` | No | — | UDP/137; no args needed. |
| `vulners` | No | `mincvss=7`, `vulners.showlinks=true` | Filter by severity and show links; requires internet. |

> **Bold “Yes” in Requires Args** = the script typically fails or is useless without those args.  
> For SNMP, “Yes (usually)” because modern networks disable `public`/anonymous; provide the correct community or SNMPv3 credentials.

---

## 🔬 Examples (args applied where helpful)

### SNMP v2c (most common)
```bash
nmap -sU -p161 --script=snmp-sysdescr,snmp-info <IP>   --script-args snmpcommunity=PublicRO,snmpversion=2c
```

### SNMP v3 (enterprise gear)
```bash
nmap -sU -p161 --script=snmp-interfaces,snmp-processes <IP>   --script-args snmpversion=3,snmpseclevel=authPriv,snmpauthuser=netmon,snmpauthproto=SHA,snmpauthpass='S3cretAuth!',snmpprivproto=AES,snmpprivpass='S3cretPriv!'
```

### Kerberos user enumeration (intrusive; DC only)
```bash
nmap -p88 --script=kerberos-enum-users <DC>   --script-args userdb=users.txt,domain=EXAMPLE.COM,kdc=dc1.example.com
```

### LDAP with credentials
```bash
nmap -p389,636 --script=ldap-rootdse,ldap-naming-contexts <IP>   --script-args ldap.username='CN=reader,OU=Svc,DC=example,DC=com',ldap.password='P@ssw0rd!'
```

### SMB with credentials (stronger enumeration)
```bash
nmap -p445 --script=smb-os-discovery,smb-enum-shares <IP>   --script-args smbusername=svc_scan,smbpassword='VeryS3cure!',smbdomain=EXAMPLE
```

### HTTP NTLM info with explicit domain/workstation
```bash
nmap -p80,443 --script=http-ntlm-info <IP>   --script-args ntlm.domain=EXAMPLE,ntlm.workstation=SCANNER01
```

### SIP over UDP with method tuning
```bash
nmap -sU -p5060 --script=sip-methods <IP>   --script-args sip.transport=udp,sip.methods=INVITE,OPTIONS,REGISTER
```

### Broadcast with newtargets
```bash
nmap --script=broadcast-upnp-info --script-args newtargets
```

### Filter CVEs by severity using vulners
```bash
nmap -sV --script=vulners --script-args mincvss=7,vulners.showlinks=true <IP>
```

---

## ✅ Practical Tips (unchanged)
1. Run as root/Administrator for raw socket access.  
2. Use `--defeat-rst-ratelimit` if firewalls throttle responses.  
3. Mix TCP + UDP scans for full coverage.  
4. Scripts like `kerberos-enum-users` or `smtp-enum-users` can be intrusive — check ROE.  
5. Highest accuracy = correlation of multiple signals (stack + banners + SMB/SNMP/LDAP).  

---

This README is **ready for GitHub** and focuses specifically on **which scripts need args** and **which args improve results**.
