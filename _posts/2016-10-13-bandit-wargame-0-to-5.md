---
layout: post
title: Bandit CTF writeup [0-5]
categories: [ctf]
tags: [writeups, infosec, ctf, wargame]
fullview: false
comments: true
---
## Bandit 0
Too obvious for a writeup... Ok, just a simple SSH

    $ ssh bandit0@bandit.labs.overthewire.org

When prompted to insert the password, go for *bandit0*. Once logged in, let's se what is in there:

    bandit0@melinda:~$ ls
    readme

Checking the content of the only file:

    bandit0@melinda:~$ cat readme 
    boJ9jbbUNNfktd78OOpsqOltutMc3MY1

The result is an ugly password. Don't waste your time trying to figure out if it is a hash, base64, permutation or any stuff like that. Just use it as the password for level 1. Plain simple.

## Bandit 1
After logging into level 1 using the password we found in the last level:

    bandit1@melinda:~$ ls
    -

Hm, a file named -. Well, that is odd. If we try to check the contents of the file the way we did in level0 it is not going to work. In fact, it will halt and wait for our input.

### What happened?

Using - as a reference to stdin is a popular convention in the \*nix world. Nothing actually related to the kernel, it is just a common kind of abreviation to stdin programmers use (and must implement in case they want to use it). In the case of *cat* program, it does is implemented.

But what exactly does stdin mean? Let us see what the official documentation has to say about it (READ THE DOCS!):

    $ man stdin

So every program running in an unix envirnment should normally have 3 standard I/O streams:

* stdin - the input to it
* stdout - its output
* stderr - diagnostic/error messages

By default, all of these streams are attached to tty4, aka your beautiful black terminal. In this case your terminal receives the input to the program and also prints its output and error messages.

According to *cat* manual (again, READ THE DOCS):

    With no FILE, or when FILE is -, read standard input.

What happened when we tried to cat our weird named file is that we are actually telling the program to read the stdin stream. This means we are asking the *cat* program to receive our command and so it halts.

### Solution

In order to solve this tricky situation we must explicitly tell *cat* we do not want it to read stdin, but our beloved file. The solution is to pass a more complete path to the file. Some solutions:

    bandit1@melinda:~$ cat ./-  
    CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
    bandit1@melinda:~$ cat ~/-
    CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
    bandit1@melinda:~$ pwd
    /home/bandit1
    bandit1@melinda:~$ cat /home/bandit1/-
    CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

## Bandit 2
Checking the files in the current directory:

    bandit2@melinda:~$ ls
    spaces in this filename

When we try to print the file's content the way it is written above we will find some ugly errors:

    bandit2@melinda:~$ cat spaces in this filename
    cat: spaces: No such file or directory
    cat: in: No such file or directory
    cat: this: No such file or directory
    cat: filename: No such file or directory

### What happened?
The trick here is that spaces are somewhat special charachters (along with others like \*, $ or ") that must be *escaped* in order to work the way we intend in this case, i.e., a normal character belonging to the filename.

Let me explain. Some chars represent important symbols to the terminal. Indeed, the bash linux terminal is very closely related to the bash script language. This means whenever you type a symbol belonging to the bash scripting language the shell will try to interpret it as if it was part of a *code*.

Spaces are intepreted as commands separators in bash. This is why we got 4 lines of errors in our previous attempt to cat the file. What the shell reads is "cat the file named 'spaces', then cat the other file named 'in'..." and so on so forth.

### Solution
Whenever we do not want a bash symbol to be interpreted, i.e. read as code instead of an innocent character, we must *escape* it. The way we do it is by prepending a backslash to our char.

    bandit2@melinda:~$ cat spaces\ in\ this\ filename 
    UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

Note: if you type "cat spaces" and press tab 2 times it will autocomplete the name of the file and automatically escape its patological characters.

## Bandit 3
This time when we list the contents of the current directory we will find another directory instead of a simple file. Well, actually directories *are* files in *nix*, just like everything else. My point here is we must move into this other directory and check what is there inside of it:

    bandit3@melinda:~$ ls -l 
    total 4
    drwxr-xr-x 2 root root 4096 Nov 14  2014 inhere
    bandit3@melinda:~$ cd inhere/
    bandit3@melinda:~/inhere$ ls
    bandit3@melinda:~/inhere$ 

Oh no, it seems to be empty!

### What happened?
Some files in *nix* are said to be *hidden*, or the so called *dot-files*. Whenever a file is prepended with a dot the bash interpreter knows it must not be displayed unless by explicit command. 

### Solution
*ls* command does one thing or another besides simply blindly listing obvious files. It has many options that go from formating the detailed output in order to make it human readable to listing hidden files (for the last time, READ THE DOCS).

    bandit3@melinda:~/inhere$ ls -a
    .  ..  .hidden

Now we can see there is a *.hidden* file inside of this directory!

    bandit3@melinda:~/inhere$ cat .hidden 
    pIwrPrtPN36QITSp3EQaw936yaFoFgAB

## Bandit 4
This time we do not have a problem in the sense of the previous levels. Instead we are now presented with a directory containing some files. The stupid way to solve it is to manually cat one by one until something like the previous passwords shows up. A better approach is to write a one-liner script that automatically does this dirty job for us (remeber I said the shell is actually an interpreter?).


    bandit4@melinda:~$ cd inhere/
    bandit4@melinda:~/inhere$ for f in ./\*; do cat $f; echo; done
 
    ;�-i�(��z��У��ޘ��8鑾
    ?�@c
        O8�L��c�Ч7�zb~��ף���U�
    �g�f�4�6+>"��B�Vx��d��;de�O
    �:n����8S��Ѕ[�/q�(��@��M�.�t
    ����+��5�`�¶R
    �1*6C�u#Nr�
    ��hZ����P�邚���{#��TP��6�]��X:
    ����!��>P�
    d{����ҏH���xX|�
    koReBOKuIDDepwhWk7jZC0RTdopnAYKh
    
    cat: ./-file07~: Permission denied
    
    ��M�����#8B0wPg�����C���@��FM�
    \#[:*���?��j���U�

And we can easily see the noble password in the middle of the junk :)

## Bandit 5
According to the instructions in the site:

    The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties: - human-readable - 1033 bytes in size - not executable

There are many ways to accomplish this level. In fact, there is an overhead of information in the challenge description. If we search only for the files with 1033 bytes we will find only one.

    bandit5@melinda:~/inhere$ find . -size 1033c
    ./maybehere07/.file2
    bandit5@melinda:~/inhere$ cat maybehere07/.file2 
    DXjZPULLxYr17uwoI01bNLQbtFemEgo7

A somewhat more complete solution would be:

    bandit5@melinda:~/inhere$ find . -size 1033c ! -perm +x -exec ls -lh {} +
    -rw-r----- 1 root bandit5 1.1K Nov 14  2014 ./maybehere07/.file2

