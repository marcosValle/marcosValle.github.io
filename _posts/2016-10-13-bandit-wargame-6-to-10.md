---
layout: post
title: Bandit CTF writeup [6-10]
categories: [ctf]
tags: [writeups, infosec, ctf, wargame]
fullview: false
comments: true
---
## Bandit 6
The first thing that came to my mind here was simply to keep using *find*'s powerful options. So now we add *-user* and *-group* in order to restrict our search. Also, we must search the whole tree of directories, not only *home* folder:

    bandit6@melinda:/$ find / -size 33c -user bandit7 -group bandit6

The problem with this solution is that a bunch of "Permission denied" warnings pop out on the screen, making it harder for us to find the target file.

### What happened?
Since we are now searching from the root of the tree downwards, we stumble in many files we do not have permission to touch.

### Solution
In a previous level we learned every Unix program normally has 3 I/O streams, one of them called *stderr*. Also, remember that *stderr* is represented as 2. To make the output of our search clearer we want to shut those annoying "Permission denied" error messages up. So we simply redirect them to the neverending well of unuseful stuff. The Unix system's black hole. The real void. The */dev/null*.

    bandit6@melinda:/$ find / -size 33c -user bandit7 -group bandit6 2>/dev/null
    /var/lib/dpkg/info/bandit7.password
    bandit6@melinda:/$ cat /var/lib/dpkg/info/bandit7.password
    HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

Much better now :)

## Bandit 7
Before diving into the solution let us check some borderline conditions:

    bandit7@melinda:~$ ls -lh
    total 4.0M
    -rw-r----- 1 bandit8 bandit7 4.0M Nov 14  2014 data.txt

    bandit7@melinda:~$ file data.txt 
    data.txt: UTF-8 Unicode text

    bandit7@melinda:~$ wc -c data.txt 
    4184396 data.txt

We have a 4MB text file, meaning there are 4184396 characters in it! Too big to just go sneaking around.

One of the multiple available solutions is to cat the file and pipe it to the *grep* tool. This way we might extract just the line in which the word "millionth" appears.

    bandit7@melinda:~$ cat data.txt | grep millionth
    millionth   cvX2JJa4CFALtqS87jk27qwqGhBM9plV

## Bandit 8
Our data.txt is still a big text file, so we will need to process it instead of searching like fools. Our friendly tools this time are *uniq* and *sort*.

Since the passoword is the only non-repeating line in the file, *uniq* is the obvious choice. According to man:

~~~
uniq - report or omit repeated lines
...
DESCRIPTION
Filter  adjacent  matching lines from INPUT (or standard input), writing to OUTPUT (or standard output).
~~~

Nevertheless, when we run it we still get a lot of text, even when using option -u for printing unique lines only.

### What happened?
*uniq* will compare **adjacent** lines, according to the man page. This means if the repeated line is not immediately before or after its twin, uniq will not filter them.

### Solution
This is where *sort* comes in. We first sort the lines of the file alphabetically and then apply the *uniq* filter over the result (we *pipe* the commands):

    bandit8@melinda:~$ sort data.txt | uniq -u
    UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

The good thing here is we do not even need *cat*, since *sort* writes its output to stdout :)

## Bandit 9
This time our *data.txt* has some binary data and a password somewhere in the middle of the junk, prepended by "several '=' characters".

The most immediate way I could think was to grep '=='. As expected it does not work and we receive:


### What happened?
Why can't a simple *grep* solve it? Let's check:

    bandit9@melinda:~$ grep '==' data.txt
    Binary file data.txt matches

Hm, it seems it thinks the file contains binary data. Let's check a little deeper:

~~~
bandit9@melinda:~$ od -c data.txt
...
0045520 300 334   b   * 347 360 350   1   K 355 335 026   k 004 220 214
0045540   4   -   = 002 307   % 216   h 376   ] 350 201 243   i  \n   H
0045560 210 237   { 235   ^ 367 255   \   P 376   _   7 246 213   S 244
0045600 267   w 233 347  \b 031   C   _ 304   p 377 260   ^ 242 354 325
0045620 356   .   4   J 232  \b 214   v   z 310 214   p   J 036 307   D
0045640 372 246 235 216 226 225   y 003 236 320  **\0**  \f 350   ?   5 223
0045660 266 204 245
0045663
~~~

So you see, there is at least one **\0** character, which is enough for grep to consider the whole file as a binary. Because of this it will deliver that annoying message.

### Solution(s)
There are too many ways to solve it. Basically we want the tool we are going to use to interpret whatever it reads as text, not binary.

~~~
bandit9@melinda:~$ grep -a '==' data.txt
�f�����^B �ﺱ>O^FD�_^P^Q��]�dL�Q�5bʵ���N��]��^F��^]W��^Z���94��%{�%�����h��n    oX:��|^U.�U��ކ�k��f"�,�W�ſ^D�^Ax��ˋ!W^[�^X�l;l�rv��/�����P/��VX�o�*�����D�d6��.���#�v[u{m��S�[��r�Ⱦ�? 5�Nv���>h�.^\u^_�p^R��#��r@h^>U�n�#���M�`�a&bhR�^Z�k�^T�I�*���j߂
                                                                    ^T���:ih��yk�T;����v<��:E|���}�����^T����wp�s�O"��)���p$�^^�L�y L�K�    �1��+���v͋"Y�N�^[^By>P^XK�Z�-�^_ȍ�t�����@^��^]c�
                          ��ڿ��{�m��^[����g��:q���T-!u�{^R�
z哞��1cF�========== **truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk**

bandit9@melinda:~$ cat -v data.txt | grep ==
zM-eM-^SM-^^M-@M-E1cFM-u========== **truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk**
M-'{M-pM-3M-ixM-mM-^CLM-^[M-RV9p>^^^RazM-\M-g^T^V!7M-^_M-^BR#^UM-}M-^TtM-x7M-"^GM-^[M-^P^G2^TM-njM-^OM-vM-C^ATM-&M-9uI^GM- M-t_M-^On^KM-hM-^I}`M-^AM-^@y"X^B^CM-3ppM-^UM-.M-^LM-^P^PM-zmM-?n^GM-?^FYx^_^]aM-^PM-^XM-\M-^@M-oM-^E)+M-h*tM-^`M-O3-M-^]kM-qM-1y{hM-p^H#"M-_)#"M-rM-^DM-^EI^BY22fM-^EM-OM-{M-gUM-`M-b^^M-"^G^Ky$M-^RM-,M-]  M-/M-i^NM-w<^TNM-)M-K5XdM-snM-^FM-WM-7M-^GM-QM-.M-kM-eM-^@Fk8M-^HM-^Z^OM-IM-R^FM-H^PM-G M-~!lM-GM-i[M-.eM-^HzM-^F^^^S:@M-^Vx^NM-7LM-^YM-D`65M-/%M-rQM-N^QM-(M-e^M&]M-Rd^OM-_^LM-,M-^ZM-CDM-%M-JM-^PM-2X^\M-gM-W^D1M-bM-4M-DM-OM-^RM-7&MM-^D6eM-^Dw=^HM-tAM-6^HM-<^EM-*^QM-^Wf\%^@M-6M-R^YZFM-qkwlM-^TNK.M-^^^O^VzM-:M-WCS\^CM-^EHM-=-M-^T^]AM->)M-BM-sM-"M-OM-n{M-{M-uM-^RM-oM-R]M-/M-=M-^_M-3M-ZM-G<M-^V'WT$M-3M-EM-!M-xJ\M-)M-^LJM-VM-P"M-eM-sM-mM-^[M-]nM-nM-^MM-@   PM-,M-^T^R^_TyM-^W.M-^LDM-^[M-/M-q}ZM-^DM-L^Nm~M-9M-^[M-VM-^J8M-dM-vM-pM-3M-^YM-^ETM-HQ"^EkM-EM-VhM-^JM-1JM-2M-tbM-!v?4sM-^V0M-^I$jM-^Q87M-^WhM-d^NM->M-^MM-$/]^]1M-^Nl#M-jM-^AM-^?M-#b^ZM-y^DM-=M-eM-!M-^VM-^IM-^YM-lqM-\M-?M-^0M-==^D^@xp,b^ExM-wM-^_M-,M-y3M-WM-^EM-l^[M-^Yv^Y^_M-5>M-^GM-g^P+0)M-n^R    M-j:LM-?yM-hvM-dM-^\M-pwb;M-^N  M-{M-yM-i^ZM-1


*bandit9@melinda:~$ strings data.txt | grep ==
I========== the6
========== password
========== ism
========== **truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk**
~~~

Yep, I also agree the solution using strings is the simplest/most elegant :)

# Bandit 10
Base64 is one of the most important encodings in computer science. It is mostly used due to historical reasons related to compatibility. Basically it takes 3 bytes (3 \* 8 = 24 bits)and represents it as 4 chars in [a-zA-Z0-9], each spanning 6 bits (4\*6 = 24 bits). Please google it in case this seems way too odd to you.

### Solution
There are really no gotchas here. All the chall wants to show you is you can decode base64 from terminal.

~~~~
bandit10@melinda:~$ cat data.txt 
VGhlIHBhc3N3b3JkIGlzIElGdWt3S0dzRlc4TU9xM0lSRnFyeEUxaHhUTkViVVBSCg==
bandit10@melinda:~$ cat data.txt | base64 --decode
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR
~~~~
