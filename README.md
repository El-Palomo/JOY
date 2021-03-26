# JOY
Desarrollo del CTF JOY

## 1. Configuración de la VM

Descargar la VM: https://www.vulnhub.com/entry/digitalworldlocal-joy,298/

## 2. Escaneo de Puertos

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.144
Nmap scan report for 10.10.10.144
Host is up (0.00062s latency).
Not shown: 65523 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
|_drwxrwxr-x   2 ftp      ftp          4096 Jan 10  2019 upload
22/tcp  open  ssh         Dropbear sshd 0.34 (protocol 2.0)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Not valid before: 2018-12-23T14:29:24
|_Not valid after:  2028-12-20T14:29:24
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http        Apache httpd 2.4.25
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2016-07-19 20:03  ossec/
|_
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Index of /
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: SASL UIDL CAPA AUTH-RESP-CODE STLS RESP-CODES PIPELINING TOP
|_ssl-date: TLS randomness does not represent time
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: more have ENABLE listed LOGINDISABLEDA0001 IDLE LITERAL+ post-login capabilities ID OK IMAP4rev1 SASL-IR LOGIN-REFERRALS Pre-login STARTTLS
|_ssl-date: TLS randomness does not represent time
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
465/tcp open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Not valid before: 2018-12-23T14:29:24
|_Not valid after:  2028-12-20T14:29:24
|_ssl-date: TLS randomness does not represent time
587/tcp open  smtp        Postfix smtpd
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Not valid before: 2018-12-23T14:29:24
|_Not valid after:  2028-12-20T14:29:24
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imaps?
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG
| Not valid before: 2019-01-27T17:23:23
|_Not valid after:  2032-10-05T17:23:23
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3s?
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG
| Not valid before: 2019-01-27T17:23:23
|_Not valid after:  2032-10-05T17:23:23
|_ssl-date: TLS randomness does not represent time
MAC Address: 00:0C:29:4D:45:FE (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts: The,  JOY.localdomain, 127.0.1.1, JOY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -2h40m00s, deviation: 4h37m06s, median: -1s
|_nbstat: NetBIOS name: JOY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: joy
|   NetBIOS computer name: JOY\x00
|   Domain name: \x00
|   FQDN: joy
|_  System time: 2021-03-24T10:06:04+08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-24T02:06:04
|_  start_date: N/A
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy1.jpg" widht=80% />















