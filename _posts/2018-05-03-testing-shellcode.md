---
layout: post
title: Testing Shellcodes
categories: [osce]
tags: [slae, osce, re]
fullview: false
comments: true
---
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228

One key part of understanding (and testing!) shellcodes is knowing how to execute them. This is no new content and you can find multiple valuable resources explaining it out there. Hopefully this might sum up and help someone someday - besides myself :)

Every code snippet is being compiled with

    $gcc -z execstack -fno-stack-protector -m32 myWrapper.c -o myWrapper

There are two main techniques to run a shellcode. Both consist in using a small C program as a wrapper for the shellcode.

# Technique 01: using function pointers

Basically, we are going to cast the shellcode as a function pointer and then call it. In case you are not fammiliar with function pointers, I do recommend you spend some time learning more about it. It is a powerfull resource in C that even allows you to work with the language as object oriented. Crazy, huh?

The wrapper code goes like this:

~~~
 #include<stdio.h>
 
 // From shell-storm.org
 char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                   "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"; 
 
 int main(){
     int (*ret)();
     ret = (int(*)())shellcode;
     ret();
 
     return 0;
 }
~~~

Let's break it part by part, starting with 

~~~
char \*shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                    "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
~~~

This is simply declaring a pointer to char. Nothing fancy here, as the tricky part will be executing it as a function, instead of a char.

Next, we have `int (*ret)();`. Maybe we should really understand what is going on here. How would you declare a function, say, `foo` that receives an `int` as an argument and also returns an `int`? Probably you would say something like:

    int foo(int);

What if now, instead of a function, we want a pointer to this function? It would be like any other pointer, just add an `*` before it, right?

    int * foo(int);

Although this seems correct, there is a tricky caveat here. Since `()` operator has a higher precedence than `*`, this would mean `a foo function that receives an int parameter and returns an int* value`. The solution for it is to add another pair of parenthesis so to invert the precedence order:

    int (*foo)(int);

To make things even more clear, please refer to [this place](https://www.geeksforgeeks.org/how-to-declare-a-pointer-to-a-function/). Certainly a better explanation than mine :)

So `int (*ret)();` is simple a pointer to a function that receives no arguments and returns an `int`.

Now for the most interesting part we have `ret = (int(*)())shellcode;`. Despite it seems like just another function pointer, there are a few differences. To begin with, where is `foo` in `(int(*)())shellcode`? Notice that `(int(*)())` means just the same as we did above, the only difference being there are no defined function name nor arguments. This happens because we are actually *casting* the `shellcode` pointer. Remember this pointer was originally declared as a pointer to char? After `(int(*)())shellcode`, it will be a `pointer to a function that returns an int`. Then we assign this pointer to `ret`, which you remember is of the same type.

And for the *grand finale*, we deference this pointer! Well, maybe deferencing would not be the best term here. We actually *call* this pointer, just as you would do with any regular function. Check [this](https://stackoverflow.com/questions/2795575/how-does-dereferencing-of-a-function-pointer-happen) out to learn more about deferencing function pointers.

Another way to do the same but without the variable `ret` follows below. Notice it makes the code somewhat less readable though.

~~~
 #include<stdio.h>
 
 char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
                   "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
 
 int main(){
     (*(int(*)())shellcode)();
 
     return 0;
 }
~~~

If this all still seems confusing, you may wanna try the [clockwise/spiral rule](c-faq.com/decl/spiral.anderson.html) for understanding any C code.

# Technique 02: overwriting main()'s return address

I first saw this technique in the [Shellcoder's Handbook](https://www.amazon.com.br/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X) (which is an awesome resource btw). The wrapper code is presented below.

~~~
#include<stdio.h>

char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\x31\xd2\xcd\x80";
 
int main() {
    int *ret;
    ret = (int *)&ret + 2;
    (*ret) = (int)shellcode;
}
~~~

This is somewhat simpler to understand in my opinion. Instead of calling the shellcode as a function, we are now overwriting the return address of `main()`. Something simmilar to what happens in a buffer overflow, but... well, without the overflow, of course. Remember how the local variables are followed by EBP and EIP? That is why we add 2 to the address of our shellcode. So with `ret = (int *)&ret + 2;` we actually make `ret` point to the return address of `main()`. Therefore, `(*ret) = (int)shellcode;` overwrites it with the address of our shellcode. Neat!

There is great explanation about it [here in this SO question](https://stackoverflow.com/questions/9816059/shellcode-in-c-what-does-this-mean). Including some clarification about the casting hell you see with `int *`.

BUT! There is a little caveat that consumed some my precious time and I would like to share with you (or my future self, in case that is who is reading it). So take a deep breath and bear with me for just a little while.

If you take a careful look at this shellcode you might notice something different from the other one we used before. This blatant difference is in `\x31\xd2\`. Whenever we try to execute the same shellcode as before in our second wrapper we will receive an annoying SEGFAULT and no shell (please try it yourself). Let me briefly explain what happens.

The shellcode we used before is equivalent to:

~~~
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80
~~~

From `mov $0xb,%al` we know we are using the `SYS_EXECVE` syscall. According to the [man page](http://man7.org/linux/man-pages/man2/execve.2.html):

~~~
int execve(const char *filename, char *const argv[],
           char *const envp[]);
~~~

So `execve` actually receives 3 parameters. In our shellcode, we should pass them through `ebx`, `ecx` AND `edx`. The whole problem happens because we are not setting `edx` in our shellcode. This corresponds to the third parameter, the environment array. When we execute the second wrapper it triggers a SEGFAULT, since the set `edx` by that time is something basically random, which hardly will point to a valid environment parameter.

The fix for this problem is actually set `edx` as 0, which corresponds exactly to `\x31\xd2\`.

The question now is: why did the first wrapper run and the second did not? I will let this for you to explore. Just as a hint, remember checking `edx` values used in each case. `strace` is your friend in this task.

Execve with buggy shellcode using the first wrapper:

    execve("/bin//sh", ["/bin//sh"], [/* 0 vars */]) = 0

Execve with buggy shellcode using the second wrapper:

    execve("/bin//sh", ["/bin//sh"], [/* 6 vars */]) = -1 EFAULT (Bad address)

The fixed shellcode might be found [here](https://www.exploit-db.com/exploits/39160/) with some nice ASCII schemes. Also, refer to [this SO question](https://stackoverflow.com/questions/31504984/executing-shellcode-segmentation-fault) that touches the problem.
