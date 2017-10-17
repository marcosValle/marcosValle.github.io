---
layout: post
title: Tokyo Westerns / MMA 2nd 2016 - Make a palindrome!
categories: [ctf]
tags: [writeups, infosec, ctf, ppc]
fullview: false
comments: true
---
> Your task is to make a palindrome string by rearranging and concatenating given words.
>
> Input Format: N <Word_1> <Word_2> ... <Word_N>
> Answer Format: Rearranged words separated by space.
> Each words contain only lower case alphabet characters.
> 
> Example Input: 3 ab cba c
> Example Answer: ab c cba
>
> You have to connect to ppc1.chal.ctf.westerns.tokyo:31111(TCP) to answer the problem.
> 
> $ nc ppc1.chal.ctf.westerns.tokyo 31111
>
> * Time limit is 3 minutes.
> * The maximum number of words is 10.
> * There are 30 cases. You can get flag 1 on case 1. You can get flag 2 on case 30.
> * samples.7z Server connection examples.

We used pwntools to solve it even though the organizers gave a code for connecting with the server (?). No way we should use it :)

~~~
from pwn import *
import itertools

def rearrange(words):
    combinations = itertools.permutations(words)
    return combinations

def checkPal(combinations):
    for comb in combinations:
       possiblePal = ''.join(comb)
       if possiblePal==possiblePal[::-1]:
           possiblePal[::-1] 
           pal = ' '.join(comb)
           return pal 
   
r = remote('ppc1.chal.ctf.westerns.tokyo', 31111)
r.recvuntil('play!')

i=1
while i<31:
    print(r.recvuntil('Input: '))

    inputStr = r.recvuntil('\n')
    words = inputStr.split()
    words.pop(0)
    combinations = rearrange(words)
    pal = checkPal(combinations)
    print(pal)
    r.sendline(pal)
    i = i+1 

print(r.recvline())
r.close()
~~~~

FLAG 1: TWCTF{Charisma_School_Captain}\\
FLAG 2: TWCTF{Hiyokko_Tsuppari}

