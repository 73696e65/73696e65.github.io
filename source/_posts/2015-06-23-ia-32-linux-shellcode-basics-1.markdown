---
layout: post
title: "IA-32 Linux Shellcode Basics 1"
date: 2015-06-23 15:01:28 +0200
comments: true
categories: [exploit, shellcode]
---
We start with the simple shellcode, that prints `hello` string. For this
purpose, we use Kali Linux 32 bit distribution, that could be downloaded
[here](https://www.kali.org/downloads/). 

Because we want to have code as simple as possible, we use tcc ansi compiler and
nasm assembler.

{% codeblock %}
root@kali32:~# aptitude install tcc nasm
{% endcodeblock %}

{% codeblock lang:c hello.c %}
#include <stdio.h>

void main() {
    printf("hello\n");
}
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# tcc -g hello.c -o hello

root@kali32:/tmp# echo 'set disassembly-flavor intel' >> ~/.gdbinit

root@kali32:/tmp# gdb -q ./hello -ex 'disassemble main' --batch
BFD: /tmp/hello: no group info for section .text.__i686.get_pc_thunk.bx
BFD: /tmp/hello: no group info for section .text.__i686.get_pc_thunk.bx
Dump of assembler code for function main:
   0x080481e4 <+0>:	push   ebp
   0x080481e5 <+1>:	mov    ebp,esp
   0x080481e7 <+3>:	sub    esp,0x0
   0x080481ed <+9>:	mov    eax,0x8049304
   0x080481f2 <+14>:	push   eax
   0x080481f3 <+15>:	call   0x80482e0 <printf>
   0x080481f8 <+20>:	add    esp,0x4
   0x080481fb <+23>:	leave  
   0x080481fc <+24>:	ret    
End of assembler dump.
{% endcodeblock %}

As we can see, the string is located at `0x08049304` address. However, our code
should be Position Independent (PIE) and without NULL characters.

To rewrite the code about, we need to:

- Look up the number corresponding to the system call in `/usr/include/i386-linux-gnu/asm/unistd_32.h`
- Place system call number in eax, and arguments in ebx, ecx, edx... in the order they appear in the corresponding man page
- Execute `int 0x80` to alert the kernel we want to perform a system call

Our first try:
{% codeblock lang:asm hello1.asm %}
section .data
msg db 'hello',0xa

section .text
global _start
_start:

;write(int fd, char *msg, unsigned int len)
mov eax, 4
mov ebx, 1
mov ecx, msg
mov edx, 6
int 0x80

;exit(int ret)
mov eax,1
mov ebx,0
int 0x80

{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf hello1.asm; ld hello1.o -o hello1

root@kali32:/tmp# ./hello1 
hello
{% endcodeblock %}

Dumping instruction bytecode:
{% codeblock %}
root@kali32:/tmp# objdump -d hello1 -M intel

hello1:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	b8 04 00 00 00       	mov    eax,0x4
 8048085:	bb 01 00 00 00       	mov    ebx,0x1
 804808a:	b9 a4 90 04 08       	mov    ecx,0x80490a4
 804808f:	ba 06 00 00 00       	mov    edx,0x6
 8048094:	cd 80                	int    0x80
 8048096:	b8 01 00 00 00       	mov    eax,0x1
 804809b:	bb 00 00 00 00       	mov    ebx,0x0
 80480a0:	cd 80                	int    0x80
{% endcodeblock %}

When we set 32b register with a small value, the compiler fills the unused
space with zeros.  Instead, we should use AX = 16b or AL = 8b register parts
(in the case of register EAX).

Next try:

{% codeblock lang:asm hello2.asm %}
section .data
msg db 'hello',0xa

section .text
global _start
_start:

;write(int fd, char *msg, unsigned int len)
mov al, 4
mov bl, 1
mov ecx, msg
mov dl, 6
int 0x80

;exit(int ret)
mov al,1
mov bl,0
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf hello2.asm; ld hello2.o -o hello2

root@kali32:/tmp# ./hello2 
hello

root@kali32:/tmp# objdump -d hello2 -M intel

hello2:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	b0 04                	mov    al,0x4
 8048082:	b3 01                	mov    bl,0x1
 8048084:	b9 94 90 04 08       	mov    ecx,0x8049094
 8048089:	b2 06                	mov    dl,0x6
 804808b:	cd 80                	int    0x80
 804808d:	b0 01                	mov    al,0x1
 804808f:	b3 00                	mov    bl,0x0
 8048091:	cd 80                	int    0x80
{% endcodeblock %}

We attempt to make the code position independent pushing string to the stack:

{% codeblock lang:asm hello3.asm %}
section .text
global _start
_start:

;clear out the registers we are going to need
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

;write(int fd, char *msg, unsigned int len)
mov al, 4
mov bl, 1
push 0x58580a6f ; push X, X, \n, o
push 0x6c6c6568 ; push l, l, e, h
mov ecx, esp
mov dl, 6
int 0x80

;exit(int ret)
mov al,1
xor ebx, ebx
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf hello3.asm; ld hello3.o -o hello3

root@kali32:/tmp# ./hello3 
hello

root@kali32:/tmp# objdump -d hello3 -M intel

hello3:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	31 db                	xor    ebx,ebx
 8048064:	31 c9                	xor    ecx,ecx
 8048066:	31 d2                	xor    edx,edx
 8048068:	b0 04                	mov    al,0x4
 804806a:	b3 01                	mov    bl,0x1
 804806c:	68 6f 0a 58 58       	push   0x58580a6f
 8048071:	68 68 65 6c 6c       	push   0x6c6c6568
 8048076:	89 e1                	mov    ecx,esp
 8048078:	b2 06                	mov    dl,0x6
 804807a:	cd 80                	int    0x80
 804807c:	b0 01                	mov    al,0x1
 804807e:	31 db                	xor    ebx,ebx
 8048080:	cd 80                	int    0x80
{% endcodeblock %}

Now it looks good, but the 0x0a could sometimes terminate the buffer
prematurely, so we simply do not use this character.

{% codeblock lang:asm shell4.asm %}
section .text
global _start
_start:

;clear out the registers we are going to need
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

;write(int fd, char *msg, unsigned int len)
mov al, 4
mov bl, 1
push 0x5858586f ; push X, X, X, o
push 0x6c6c6568 ; push l, l, e, h
mov ecx, esp
mov dl, 5
int 0x80

;exit(int ret)
mov al,1
xor ebx, ebx
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf hello4.asm; ld hello4.o -o hello4
root@kali32:/tmp# ./hello4 
hello

root@kali32:/tmp# objdump -d hello4 -M intel

hello4:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    eax,eax
 8048062:	31 db                	xor    ebx,ebx
 8048064:	31 c9                	xor    ecx,ecx
 8048066:	31 d2                	xor    edx,edx
 8048068:	b0 04                	mov    al,0x4
 804806a:	b3 01                	mov    bl,0x1
 804806c:	68 6f 58 58 58       	push   0x5858586f
 8048071:	68 68 65 6c 6c       	push   0x6c6c6568
 8048076:	89 e1                	mov    ecx,esp
 8048078:	b2 05                	mov    dl,0x5
 804807a:	cd 80                	int    0x80
 804807c:	b0 01                	mov    al,0x1
 804807e:	31 db                	xor    ebx,ebx
 8048080:	cd 80                	int    0x80
{% endcodeblock %}

Now we parse out the opcodes and validate the functionality. 

{% codeblock %}
root@kali32:/tmp# objdump -d hello4 | tr '[:blank:]' '\n' | egrep '^[0-9a-f]{2}$' | sed 's#^#\\x#' | paste -s -d ''
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x68\x6f\x58\x58\x58\x68\x68\x65\x6c\x6c\x89\xe1\xb2\x05\xcd\x80\xb0\x01\x31\xdb\xcd\x80
{% endcodeblock %}

If we want to store shellcode to the file:
{% codeblock %}
root@kali32:/tmp# sc=$(objdump -d hello4 | tr '[:blank:]' '\n' | egrep '^[0-9a-f]{2}$' | sed 's#^#\\x#' | paste -s -d '')

root@kali32:/tmp# echo $sc | ruby -e 'print $stdin.read.scan(/\\x(..)/).flatten.map{ |x| x.to_i(16).chr }.join' > hello.shellcode

root@kali32:/tmp# hexdump -C hello.shellcode 
00000000  31 c0 31 db 31 c9 31 d2  b0 04 b3 01 68 6f 58 58  |1.1.1.1.....hoXX|
00000010  58 68 68 65 6c 6c 89 e1  b2 05 cd 80 b0 01 31 db  |Xhhell........1.|
00000020  cd 80                                             |..|
00000022
{% endcodeblock %}

{% codeblock lang:c test.c %}
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

char sc[]= "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x68\x6f\x58\x58\x58\x68\x68\x65\x6c\x6c\x89\xe1\xb2\x05\xcd\x80\xb0\x01\x31\xdb\xcd\x80";

int main(){
        void * a = mmap(0, 4096, PROT_EXEC |PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
        printf("allocated executable memory at: %p\n", a); 
        ((void (*)(void)) memcpy(a, sc, sizeof(sc)))();
}
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# gcc test.c -o test

root@kali32:/tmp# ./test 
allocated executable memory at: 0xb7734000
hello
{% endcodeblock %}

Our next step will be to execute shell.
