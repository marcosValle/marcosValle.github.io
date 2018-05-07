---
layout: post
title: JMP/CALL/POP technique in depth
categories: [osce]
tags: [slae, osce, re]
fullview: false
comments: true
---

A really nice trick for writing x86 shellcode I learned during SLAE is the so called *JMP/CALL/POP* technique. Basically, we are trying to achieve two goals with it:

1. Avoid any  NULLs
2. Avoid hardcoded addresses

Although there are multiple examples out there, I felt like none of them explained deeper *why* this technique goes the way it is. Keep in mind that the key point here is to learn how to dynamically resolve a string address.

Let's begin with a simple `execve` shellcode.

~~~
; execve.nasm

section .text

global _start

_start:

    xor eax, eax
    mov al, 0xb

    mov ebx, shell

    xor ecx, ecx
    xor edx, edx

    int 0x80

section .data

    shell db  '/bin/sh'
~~~

All this shellcode does is setting the necessary registers with appropriated values and then calling `int 0x80` to run the `execve` syscall. Notice we did put the `/bin/sh` string in the *data* section in order to explain the objective of this technique.

Also, we are not expecting any NULLs

Now assemble and link:

    $nasm -f elf32 execve.nasm -o execve.o
    $ld -m elf_i386 execve.o -o execve

Let's check the opcodes:

~~~
$objdump -d execve

execve:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    %eax,%eax
 8048082:	b0 0b                	mov    $0xb,%al
 8048084:	bb 90 90 04 08       	mov    $0x8049090,%ebx
 8048089:	31 c9                	xor    %ecx,%ecx
 804808b:	31 d2                	xor    %edx,%edx
 804808d:	cd 80                	int    $0x80
~~~

Awesome, no null bytes as expected. However, we have `mov    $0x8049090,%ebx`. This line indicates we are using a hardcoded address (the shellcode string address). To avoid it and therefore make our shellcode more reliable, we are going to apply the JMP/CALL/POP technique.

# Why CALL/POP?

IMHO it is easier to understand JMP/CALL/POP if we first analyse the CALL/POP part. The idea is to explore the fact that whenever you `CALL` something, the first thing it does is pushing the next instruction address into the stack.

Consider this snippet:

~~~
section .text

global _start

_start:
    call realStuff
    shell: db  '/bin/sh', 0

realStuff:

    xor eax, eax
    mov al, 0xb

    pop ebx

    xor ecx, ecx
    xor edx, edx

    int 0x80
~~~

The first thing this program actually does is calling `realStuff` procedure. Differently from a `JMP` instruction, the `CALL` instruction sets a new stack frame, i.e., it saves a bunch of registers using the stack so it can come back to where it were once the procedure is finished. As I said before, one of the saved values is the next instruction address. When the procedure `ret`s, this value is popped from the stack right into EIP, so the execution flow can go on.

The interesting point is that by setting our `/bin/sh` string right after `call` means its address is going to be saved into the stack. This is awesome because once we are inside `realStuff` we can simply pop it into `ebx`, avoiding the need to hardcode any addresses!

Just to make things clear, please notice I added a 0 in order to make our string null terminaded. Otherwise there would be lots of gibberish in ebx and execve would not be called correctly.

Check the opcodes yourself:

~~~
$ objdump -d execve

execve:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	e8 08 00 00 00       	call   804806d <realStuff>

08048065 <shell>:
 8048065:	2f                   	das    
 8048066:	62 69 6e             	bound  %ebp,0x6e(%ecx)
 8048069:	2f                   	das    
 804806a:	73 68                	jae    80480d4 <realStuff+0x67>
	...

0804806d <realStuff>:
 804806d:	31 c0                	xor    %eax,%eax
 804806f:	b0 0b                	mov    $0xb,%al
 8048071:	5b                   	pop    %ebx
 8048072:	31 c9                	xor    %ecx,%ecx
 8048074:	31 d2                	xor    %edx,%edx
 8048076:	cd 80                	int    $0x80
~~~

See, no more hardcoded addresses. Great, but it seems we have solved one problem and created another. Our `call` instruction resulted in `e8 08 00 00 00`. Lots of NULLs! This leads us to the next part of the technique.

# Why JMP?

So we are going to use JMP to solve the added NULLs problem. But in order to understand how, one must comprehend the different types of JMP:

* Short JMP
* Near JMP
* Far (long) JMP

Whenever you type a `JMP` instruction in your assembly code you might define the specific type of JMP. However, if you do not, NASM (and a few other assemblers) will do it for you. That is a good reason why we have [two-pass assemblers](http://users.cis.fiu.edu/~downeyt/cop3402/two-pass.htm).

I suggest you to play with these parameters in your code. Short JMP is the key to our problem, so I also recommend you check [here](http://thestarman.pcministry.com/asm/2bytejumps.htm) how it works.

In short, short JMP (no pun intended) means we will use 2 bytes only to jump to a memory location in the same segment. The first byte is always `EB`, so we actually have `2^8=256` bytes for our offset. In fact, we use a signed offset, so it actually goes from 00h to 7Fh for a forward JMP and from 80h to FFh for a backward JMP. This is great because it means using a `JMP short` instruction will not add any NULLs.

Back to our problem, things get really interesting in fact when we realize that `CALL` *extends sign* across the upper bytes. So if we are calling an address lower than where we currently are, there will probably be lot's of `1`s in the opcodes instead of `0`s. The idea therefore is to put our `CALL` instruction *after* `realStuff`, so all those `0`s can gracefully become `1`s!


# Final code

This is what we get after doing it:

~~~
 section .text
 
 global _start
 
 _start:
 
 jmp short hack
 
 realStuff:
 
     xor eax, eax
     mov al, 0xb
 
     pop ebx
 
     xor ecx, ecx
     xor edx, edx
 
     int 0x80
 
 hack:
     call realStuff
     shell: db  '/bin/sh'
~~~

`CALL` is now inside `hack`, which is after (higher memory address) than `realStuff`. We accomplished

Let's check the opcodes:

~~~
$ objdump -d execve

execve:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	eb 0b                	jmp    804806d <hack>

08048062 <realStuff>:
 8048062:	31 c0                	xor    %eax,%eax
 8048064:	b0 0b                	mov    $0xb,%al
 8048066:	5b                   	pop    %ebx
 8048067:	31 c9                	xor    %ecx,%ecx
 8048069:	31 d2                	xor    %edx,%edx
 804806b:	cd 80                	int    $0x80

0804806d <hack>:
 804806d:	e8 f0 ff ff ff       	call   8048062 <realStuff>

08048072 <shell>:
 8048072:	2f                   	das    
 8048073:	62 69 6e             	bound  %ebp,0x6e(%ecx)
 8048076:	2f                   	das    
 8048077:	73 68                	jae    80480e1 <shell+0x6f>
~~~

Awesome! No hardcoded addresses OR NULLs! This is the tricky magic of the *JMP/CALL/POP* technique :)
