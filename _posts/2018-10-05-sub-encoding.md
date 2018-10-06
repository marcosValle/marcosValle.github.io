---
layout: post
title: SUB encoding
categories: [re,exploit]
tags: [osce]
fullview: false
comments: true
---

Sometimes during the exploit development you may find yourself in a situation where you need to write an address to a buffer but some of its bytes are badchars. An interesting approach is to manually encode the address using only `SUB` operations and a bit of arithmetics. You can find a great explanation [here](https://vellosec.net/2018/08/carving-shellcode-using-restrictive-character-sets/)

Suppose `ESP` points to the address `0x1035E8EA` but for some reason you need it to point to `0x1035FFB4`. However you can only use alphanumeric characters. If you try simply to `mov ESP, 0x1035FFB4` you will most certainly face a badchar hell. However, if you subtract `X` from `ESP` you might wrap up into the desired address `ESP'`. Here is what I mean:

~~~
ESP' = ESP - X
X = ESP - ESP'
X = 0 + ESP - ESP'
X = (0xFFFFFFFF + 1) + ESP - ESP'
~~~

In our example:

~~~
X = 0xFFFFFFFF + 1 + 0x1035E8EA - 0x1035FFB4
X = 0xFFFFE936
~~~

Now all we have to do is finding a few numbers (32 bits each) that sum up to `X`. Let's pick 3 of such numbers:

    X = A + B + C

Since we want alphanumeric bytes, a nice trick is to divide each byte in `X` for 3. This will give us number close to the valid interval we want. After that we can adjust the values to get exactly the byte we want. For example:

~~~
0x6F/3 = 0x23
~~~

The problem is: what if our byte is too small and dividing it by three drives us even further away from the desired interval? In this case we can multiply it by 0x100 and use the carry in the next byte computation. That is why it is extremely important to start from the least significant byte.

~~~
0x36/3 = 0x12
# Mutiply by 0x100
0x136/3 = 0x67.555...

a4 = 0x64
b4 = 0x65
c4 = 0x6D
~~~

Notice how we had to adjust `C` due to the fact that 0x112 is not a mulitple of 3. Also, since there is a carry, the next byte will be reduced by 1.

~~~
0xE8/3 = 0x4D.555...

a3 = 0x4A
b3 = 0x4B
c3 = 0x53
~~~

The next 2 bytes will be the same:

~~~
0xFF = 0x55

a1 = a2 = 0x55
b1 = b2 = 0x55
c1 = c2 = 0x55
~~~

Finally, here are our numbers:

~~~
A = 0x55554A64
B = 0x55554B65
C = 0x5555536D
~~~

Converting it into x86 instructions:

~~~
push esp                ;esp = 0x1035E8EA
pop eax                 ;get ESP in EAX
sub eax, 0x55554A64     ;eax = 0xBAE09E86
sub eax, 0x55554A65     ;eax = 0x658B5421
sub eax, 0x5555536D     ;eax = 0x103600B4
push eax
~~~

A very useful application of this techinique comes up if we consider that instead of `ESP` and `ESP'` we choose another register, ie `EAX` and `EAX'`, with `EAX = 0`. That means that by zeroing `EAX` out, we can encode any address we want. For instance:

~~~
EAX = 0
EAX' = 0x6c6e2177

X = 0xFFFFFFFF + 1 + 0 - EAX' 
X = 0x9391DE89
~~~

Applying the same algorithm we can get the following numbers:

~~~
A = 0x4b3b422d
B = 0x2128403b
C = 0x272e5c21
~~~

# Automating with z3 (z3ncoder)
> Z3 is a theorem prover from Microsoft Research. It is licensed under the MIT license.

Z3 is an awesomer tool that uses SMT/SAT solving techinques to prove multiple kinds of theorems. But worry not: it is way simpler to use than it sounds from the description. 

There is a python module named `z3-solver` that makes our life really easier. In short, all you have to do is to define a few constraints and let it give you a model. I created a simple script named [z3ncoder](https://github.com/marcosValle/z3ncoder) to illustrate what I mean.

~~~
#!/usr/bin/env python

from z3 import *
import argparse

def solve(b):
    x1 = Int('x1')
    x2 = Int('x2')
    x3 = Int('x3')
    x4 = Int('x4')
    y1 = Int('y1')
    y2 = Int('y2')
    y3 = Int('y3')
    y4 = Int('y4')
    z1 = Int('z1')
    z2 = Int('z2')
    z3 = Int('z3')
    z4 = Int('z4')
    X = Int('X')
    Y = Int('Y')
    Z = Int('Z')

    s = Solver()
    s.add(Or(X+Y+Z==b, X+Y+Z==0x100000000 + b))

    s.add(0x1000000*x1 + 0x10000*x2 + 0x100*x3 + x4 == X)
    s.add(0x1000000*y1 + 0x10000*y2 + 0x100*y3 + y4 == Y)
    s.add(0x1000000*z1 + 0x10000*z2 + 0x100*z3 + z4 == Z)

    s.add(x1>0x20, x1<0x80, x1!=0x0A, x1!=0x0D, x1!=0x2F, x1!=0x3A, x1!=0x3F)
    s.add(x2>0x20, x2<0x80, x2!=0x0A, x2!=0x0D, x2!=0x2F, x2!=0x3A, x2!=0x3F)
    s.add(x3>0x20, x3<0x80, x3!=0x0A, x3!=0x0D, x3!=0x2F, x3!=0x3A, x3!=0x3F)
    s.add(x4>0x20, x4<0x80, x4!=0x0A, x4!=0x0D, x4!=0x2F, x4!=0x3A, x4!=0x3F)
    s.add(y1>0x20, y1<0x80, y1!=0x0A, y1!=0x0D, y1!=0x2F, y1!=0x3A, y1!=0x3F)
    s.add(y2>0x20, y2<0x80, y2!=0x0A, y2!=0x0D, y2!=0x2F, y2!=0x3A, y2!=0x3F)
    s.add(y3>0x20, y3<0x80, y3!=0x0A, y3!=0x0D, y3!=0x2F, y3!=0x3A, y3!=0x3F)
    s.add(y4>0x20, y4<0x80, y4!=0x0A, y4!=0x0D, y4!=0x2F, y4!=0x3A, y4!=0x3F)
    s.add(z1>0x20, z1<0x80, z1!=0x0A, z1!=0x0D, z1!=0x2F, z1!=0x3A, z1!=0x3F)
    s.add(z2>0x20, z2<0x80, z2!=0x0A, z2!=0x0D, z2!=0x2F, z2!=0x3A, z2!=0x3F)
    s.add(z3>0x20, z3<0x80, z3!=0x0A, z3!=0x0D, z3!=0x2F, z3!=0x3A, z3!=0x3F)
    s.add(z4>0x20, z4<0x80, z4!=0x0A, z4!=0x0D, z4!=0x2F, z4!=0x3A, z4!=0x3F)

    s.check()
    s.model()
    r = []
    for i in s.model():
        r.append(s.model()[i].as_long())

    return r

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--addr", type=lambda x: (int(x,16)),
        help="Address to carve")
args = parser.parse_args()

if not args.addr:
    parser.print_help()
    parser.exit()

n = args.addr
neg = 0xFFFFFFFF - n + 1

print("Solving for 0x{:x}".format(n))
print("0xFFFFFFFF - 0x{:x} + 1 = 0x{:x}".format(n, neg)) #carry
res = solve(neg)

print('###########')
sumCheck = 0
for b in res[-3:]:
    sumCheck += b
    print(hex(b))
print('###########')

print('Check sum = {}'.format(hex(sumCheck)))
~~~

[@ihack4falafel](https://twitter.com/ihack4falafel) also created a tool way more complete than mine btw (cheers, bro!) that uses the same techinque for encoding a shellcode. You can check [Slink](https://github.com/ihack4falafel/Slink) here.
