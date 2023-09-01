---
layout: single
title: 'Bypassing ptrace anti-debugging defence in iOS applications'
description: 'This blog post focuses specifically on bypassing ptrace iOS anti-debugging defence which prevents an iOS mobile application from entering into a debugging state'
date: 2023-08-30
comments: false
classes: wide
excerpt: "This blog post focuses specifically on bypassing ptrace iOS anti-debugging defence "

header:
  teaser: /assets/images/avatar.jpg
  overlay_image: /assets/images/2023/08/ios/ptraceDisassembly.png
  overlay_filter: rgba(0, 0, 0, 0.5)

tags:
  - iOS penetration testing
  - Anti-Debugging
  - arm
  - radare2
  - r2frida
  - frida
  - r2ghidra
  - ptrace syscall
---


<br>
<h2>Introduction</h2>


<p style="text-align:justify;">
This blog post focuses specifically on dynamically bypassing  <a href="https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html"><code><b><span style="color:orange"><u>ptrace</u></span></b></code></a> iOS anti-debugging defence which prevents an iOS mobile application from entering into a debugging state. The <a href="https://rada.re/n/radare2.html"><code><b><span style="color:orange"><u>radare2</u></span></b></code></a> tool used, as well as the <a href="https://github.com/nowsecure/r2frida"><code><b><span style="color:orange"><u>r2frida</u></span></b></code></a> and <a href="https://github.com/radareorg/r2ghidra"><code><b><span style="color:orange"><u>r2ghidra</u></span></b></code></a> plugins to perform static and dynammic analysis. The <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall can be found several *nix operating systems. It is generally used for debugging breakpoints and tracing system calls. It is used from native debuggers to keep track. Also, this blog post covers only one feature of the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall, the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></i></b></code>.
</p>


<blockquote><em><p style="text-align:justify;"><b>PT_DENY_ATTACH</b>: 
                   This request is the other operation used by the traced
                   process; it allows a process that is not currently being
                   traced to deny future traces by its parent.  All other
                   arguments are ignored.  If the process is currently being
                   traced, it will exit with the exit status of ENOTSUP; oth-erwise, otherwise,
                   erwise, it sets a flag that denies future traces.  An
                   attempt by the parent to trace a process which has set this
                   flag will result in a segmentation violation in the parent.</p></em></blockquote>


<p style="text-align:justify;">
For the purpose of this blog post the <a href="https://github.com/hexploitable/r2con2020_r2frida/blob/master/ios-challenge-2.ipa"><code><b><span style="color:orange"><u>ios-challenge-2</u></span></b></code></a> application used to showcase the identification of the <code><b><i><span style="color:red">ptrace</span></i></b></code> anti-debugging technique as well as to present a way to bypass it. 
</p>


<h2>Installing r2frida plugin</h2>

<p style="text-align:justify;">
Assuming that <code><b><i><span style="color:red">radare2</span></i></b></code> is already installed on the local machine. Also, the <code><b><i><span style="color:red">r2frida</span></i></b></code> plugin will be installed which aims to join the capabilities of static analysis of <code><b><i><span style="color:red">radare2</span></i></b></code> and the instrumentation provided by frida. The recommended way to install <code><b><span style="color:red">r2frida</span></b></code> is by using <a href="https://r2wiki.readthedocs.io/en/latest/tools/r2pm/"><code><b><span style="color:red">r2pm</span></b></code></a>
</p>


<p style="text-align:justify;">
The following command will initialize the package control 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2pm init
</pre>

<p style="text-align:justify;">
Afterwards, the following command used to install <code><b><i><span style="color:red">r2frida</span></i></b></code> plugin
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2pm -ci r2frida

[....]
pkg-config --cflags r_core
-I/usr/local/Cellar/radare2/5.8.8/include/libr
cc src/io_frida.o -o io_frida.dylib -fPIC -g -L/usr/local/Cellar/radare2/5.8.8/lib -lr_core -lr_config -ldl -lr_debug -ldl -lr_bin -ldl -lr_lang -ldl -lr_anal -ldl -lr_bp -ldl -lr_egg -ldl -lr_asm -ldl -lr_flag -ldl -lr_search -ldl -lr_syscall -ldl -lr_fs -ldl -lr_magic -ldl -lr_arch -ldl -lr_esil -ldl -lr_reg -ldl -lr_io -ldl -lr_socket -ldl -lr_cons -ldl -lr_crypto -ldl -lr_util -ldl -shared -fPIC -Wl,-exported_symbol,_radare_plugin -Wl,-no_compact_unwind ext/frida/libfrida-core.a -framework Foundation -lbsm -framework AppKit -lresolv
mkdir -p /"/Users/xenovas/.local/share/radare2/plugins"
mkdir -p /"/Users/xenovas/.local/share/radare2/prefix/bin"
rm -f "//Users/xenovas/.local/share/radare2/plugins/io_frida.dylib"
cp -f io_frida.dylib* /"/Users/xenovas/.local/share/radare2/plugins"
cp -f src/r2frida-compile /"/Users/xenovas/.local/share/radare2/prefix/bin"
</pre>

<p style="text-align:justify;">
The following command shows the installed apps as well as the running apps on the virtual device 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://apps/usb
PID           Name Identifier
----------------------------
[.....]
-         Podcasts com.apple.podcasts
-        Reminders com.apple.reminders
-           Safari com.apple.mobilesafari
-         Settings com.apple.Preferences
-        Shortcuts com.apple.shortcuts
-           Stocks com.apple.stocks
-       Substitute com.ex.substitute.settings
-               TV com.apple.tv
-             Tips com.apple.tips
-        Translate com.apple.Translate
-      Voice Memos com.apple.VoiceMemos
-           Wallet com.apple.Passbook
-            Watch com.apple.Bridge
-          Weather com.apple.weather
-     iTunes Store com.apple.MobileStore
2754       DVIA-v2 com.highaltitudehacks.DVIAswiftv2
</pre>



<h2>Installing r2ghidra plugin</h2>


<p style="text-align:justify;">
In order to enhance reverse engineering capabilities provided by <code><b><i><span style="color:red">radare2</span></i></b></code> we will integrate the <code><b><i><span style="color:red">Ghidra</span></i></b></code> decompiler by installing the <code><b><i><span style="color:red">r2ghidra</span></i></b></code> plugin. The following command used to install the plugin  
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2pm -ci r2ghidra

[.....]
make install PLUGDIR=/Users/xenovas/.local/share/radare2/plugins BINDIR=/Users/xenovas/.local/share/radare2/prefix/bin
mkdir -p /Users/xenovas/.local/share/radare2/prefix/bin
cp -f sleighc /Users/xenovas/.local/share/radare2/prefix/bin
mkdir -p /Users/xenovas/.local/share/radare2/plugins
for a in *.dylib ; do rm -f "//Users/xenovas/.local/share/radare2/plugins/$a" ; done
cp -f *.dylib /Users/xenovas/.local/share/radare2/plugins
rm -f /Users/xenovas/.local/share/radare2/plugins/asm*ghidra*.dylib
rm -f /Users/xenovas/.local/share/radare2/plugins/anal*ghidra*.dylib
codesign -f -s - /Users/xenovas/.local/share/radare2/plugins/*.dylib
[....]
</pre>

<p style="text-align:justify;">
Furthermore, we should also install SLEIGH disassembler that comes with <code><b><i><span style="color:red">r2ghidra</span></i></b></code> using the following command 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2pm -ci r2ghidra-sleigh

[....]
  inflating: r2ghidra_sleigh-5.7.6/ppc_32_quicciii_le.sla
  inflating: r2ghidra_sleigh-5.7.6/JVM.ldefs
  inflating: r2ghidra_sleigh-5.7.6/6502.sla
  inflating: r2ghidra_sleigh-5.7.6/x86.sla
  inflating: r2ghidra_sleigh-5.7.6/ARM7_le.sla
  inflating: r2ghidra_sleigh-5.7.6/x86-16.pspec
  inflating: r2ghidra_sleigh-5.7.6/tricore.pspec
  inflating: r2ghidra_sleigh-5.7.6/ppc_64.cspec
  inflating: r2ghidra_sleigh-5.7.6/ARM4_le.sla
  inflating: r2ghidra_sleigh-5.7.6/riscv64-fp.cspec
  inflating: r2ghidra_sleigh-5.7.6/RV64IC.pspec
  inflating: r2ghidra_sleigh-5.7.6/x86gcc.cspec
  inflating: r2ghidra_sleigh-5.7.6/hexagon.cspec
  inflating: r2ghidra_sleigh-5.7.6/atmega256.pspec
  inflating: r2ghidra_sleigh-5.7.6/ppc_64_le.sla
  inflating: r2ghidra_sleigh-5.7.6/65c02.sla
  inflating: r2ghidra_sleigh-5.7.6/AARCH64.sla
  inflating: r2ghidra_sleigh-5.7.6/AARCH64BE.sla
  inflating: r2ghidra_sleigh-5.7.6/avr8xmega.sla
  inflating: r2ghidra_sleigh-5.7.6/ppc_64_be.sla
  inflating: r2ghidra_sleigh-5.7.6/avr8.sla
  inflating: r2ghidra_sleigh-5.7.6/ARM5_le.sla
  inflating: r2ghidra_sleigh-5.7.6/MCS96.sla
</pre>



<h2>Application dynamic analysis</h2>


<p style="text-align:justify;">
After installing and running the application it will exit immediately. 
</p>

<a href="https://xen0vas.github.io/assets/images/2023/08/ios/r_con.gif">
   <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/08/ios/r_con.gif" width="950" height="450" alt="r_con"/>
</a>


<p style="text-align:justify;">
The following command spawns the app and after exiting, the detach reason and the process termination message shows up on the output. Lets see this in practice
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://spawn/usb//re.murphy.ios-challenge-2
INFO: Using safe io mode.
 -- git pull now
[0x00000000]> INFO: DetachReason: <code><b><span style="color:red">FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED</span></b></code>
</pre>

<p style="text-align:justify;">
Now lets spawn the application again but this time we use the <code><b><i><span style="color:red">:dtf</span></i></b></code> command which traces the address of the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall and also shows the arguments in integer format
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x00000000]> oo
INFO: Using safe io mode.
INFO: resumed spawned process
[0x00000000]> :dtf ptrace ii

true
[0x00000000]> :dc
INFO: resumed spawned process
[0x00000000]> [dtf onLeave][Wed Aug 30 2023 00:57:33 GMT-0700] <code><b><span style="color:red">ptrace@0x1f9970560</span></b></code> - args: <code><b><span style="color:red">31</span></b></code>, 0. <code><b><span style="color:red">Retval: 0x0</span></b></code>
INFO: DetachReason: <code><b><span style="color:red">FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED</span></b></code>
</pre>

<p style="text-align:justify;">
As we see the application terminated again and from the args value (<code><b><i><span style="color:red">31</span></i></b></code>) we are able to determine that the feature of the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall is the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></i></b></code>.
</p>

<p style="text-align:justify;">
According with  <a href="https://github.com/OWASP/owasp-mastg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md"><code><b><span style="color:orange"><u>OWASP-MASTG and iOS Anti-Reversing Defenses</u></span></b></code></a>, the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall is not part of the public iOS API. Non-public APIs are prohibited, and the App Store may reject apps that include them. Because of this, ptrace is not directly called in the code; it's called when a ptrace function pointer is obtained via <code><b><i><span style="color:red">dlsym</span></i></b></code>. The following code snippet represents the above logic 
</p>


```c

#import <dlfcn.h>
#import <sys/types.h>
#import <stdio.h>
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
void anti_debug() {
  ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
  ptrace_ptr(31, 0, 0, 0); // PTRACE_DENY_ATTACH = 31
}

```


<h2>Application static analysis</h2>


<p style="text-align:justify;">
At this point and after we gained all the needed knowledge regarding the <code><b><i><span style="color:red">ptrace</span></i></b></code> anti-debugging technique, we can move forward to perform a static analysis. 
</p>

<p style="text-align:justify;">
First we unzip the <code><b><span style="color:red">.ipa</span></b></code> file in order to statically examine the application using <code><b><span style="color:red">radare2</span></b></code>
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ unzip ios-challenge-2.ipa
[..]
 ~/ r2 -A Payload/ios-challenge-2.app/ios-challenge-2
INFO: Analyze all flags starting with sym. and entry0 (aa)
INFO: Analyze all functions arguments/locals (afva@@@F)
INFO: Analyze function calls (aac)
INFO: Analyze len bytes of instructions for references (aar)
INFO: Check for objc references (aao)
INFO: Parsing metadata in ObjC to find hidden xrefs
INFO: Found 38 objc xrefs
INFO: Found 38 objc xrefs in 0 dwords
INFO: Finding and parsing C++ vtables (avrr)
INFO: Finding function preludes (aap)
INFO: Finding xrefs in noncode section (e anal.in=io.maps.x)
INFO: Analyze value pointers (aav)
INFO: aav: 0x100000000-0x10000c000 in 0x100000000-0x10000c000
INFO: Emulate functions to find computed references (aaef)
INFO: Type matching analysis for all functions (aaft)
INFO: Propagate noreturn information (aanr)
INFO: Use -AA or aaaa to perform additional experimental analysis
 -- Your problems are solved in an abandoned branch somewhere
[0x100008e44]> axt?
Usage: axt[?gq*]  find data/code references to this address
| axtj [addr]  find data/code references to this address and print in json format
| axtg [addr]  display commands to generate graphs according to the xrefs
| axtq [addr]  find and list the data/code references in quiet mode
| axtm [addr]  show xrefs to in 'make' syntax (see aflm and axfm)
| axt* [addr]  same as axt, but prints as r2 commands
[0x100008e44]>
</pre>

<p style="text-align:justify;">
As seen previously, the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall is generally invoked via <code><b><i><span style="color:red">dlsym</span></i></b></code> so we search for it as follows
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008e44]> axt sym.imp.dlsym
sym.func.100008864 0x100008888 [CALL:--x] bl sym.imp.dlsym
[0x100008e44]>
</pre>


<p style="text-align:justify;">
At this point we continue using <code><b><i><span style="color:red">radare2</span></i></b></code> in order to visualize the execution flow and to examine some assembly instructions in order to have insights of the validation checks in a lower level
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008e44]> s sym.func.100008864
[0x100008864]> VV
</pre>

<p style="text-align:justify;">
As we see at the screenshot below we have obtained a lot of information regarding the ptrace implementation. Specifically we see that the <code><b><i><span style="color:red">ptrace</span></i></b></code> is called by <code><b><i><span style="color:red">Challenge1.viewDidLoad</span></i></b></code> and also we are able to determine the feature of the <code><b><i><span style="color:red">ptrace</span></i></b></code> from the <code><b><i><span style="color:red">0xf1</span></i></b></code> hex value which is <code><b><i><span style="color:red">31</span></i></b></code> in decimal indicating the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></i></b></code> feature. 
</p>
<br>
<a href="https://xen0vas.github.io/assets/images/2023/08/ios/dlsym-ptrace.png">
   <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/08/ios/dlsym-ptrace.png" width="950" height="450" alt="dlsym-ptrace"/>
</a>


<p style="text-align:justify;">
At this point we are able to examine the <code><b><i><span style="color:red">viewDidLoad</span></i></b></code> method as we know it implements the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall. 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008864]> ic Challenge1
class Challenge1
0x100008a4c method Challenge1      viewDidLoad
0x100008abc method Challenge1      jailbreakTest1Tapped:
0x100008b14 method Challenge1      showAlertWithMessage:
0x100008c3c method Challenge1      isJailbroken
[0x100008864]>
</pre>

<p style="text-align:justify;">
We can see that the <code><b><i><span style="color:red">viewDidLoad</span></i></b></code> method is located at <code><b><i><span style="color:red">0x100008a4c</span></i></b></code> address as seen above, so lets further check the validations on <code><b><i><span style="color:red">radare2</span></i></b></code> 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008864]> s 0x100008a4c
[0x100008a4c]> VV
</pre>


<a href="https://xen0vas.github.io/assets/images/2023/08/ios/viewDidLoad-1.png">
   <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/08/ios/viewDidLoad-1.png" width="950" height="450" alt="viewDidLoad-1"/>
</a>

<p style="text-align:justify;">
If we examine further we see that except the ptrace syscall there are other anti-reversing defences enabled, but as we mentioned earlier this blog post is focusing only to bypass <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall. 
</p>

<p style="text-align:justify;">
Lets decompile the code using  <code><b><i><span style="color:red">r2ghidra</span></i></b></code> in order to have a high level view of the <code><b><i><span style="color:red">viewDidLoad</span></i></b></code> implementation
</p>


```c

[0x100008a4c]> pdg

void method.Challenge1.viewDidLoad(ulong param_1)

{
    int32_t iVar1;
    char *pcVar2;
    ulong uStack_20;
    ulong uStack_18;

    uStack_18 = *0x10000db80;
    uStack_20 = param_1;
    sym.imp.objc_msgSendSuper2(&uStack_20, *0x10000d958);
    sym.func.100008864();
    iVar1 = sym.func.100008a30();
    if ((iVar1 == 0) && (iVar1 = sym.func.10000898c(),  iVar1 == 0)) {
        iVar1 = sym.func.1000088b4();
        if (iVar1 == 0) {
            return;
        }
        pcVar2 = "";
    }
    else {
        pcVar2 = "";
    }
    sym.imp.NSLog(pcVar2);
    // WARNING: Subroutine does not return
    sym.imp.exit(0);
}

```

<p style="text-align:justify;">
As seen from the decompiled code above, the first check is implemnted using the <code><b><i><span style="color:red">ptrace</span></i></b></code> ( <code><b><i><span style="color:red">sym.func.100008864</span></i></b></code> ) syscall. At this point we can bypass <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall using <code><b><i><span style="color:red">r2frida</span></i></b></code> 
</p>


<h2>Hooking with r2frida</h2>


<p style="text-align:justify;">
As we saw earlier the argument passed to <code><b><i><span style="color:red">ptrace</span></i></b></code> is <code><b><i><span style="color:red">0xf1</span></i></b></code> in hex which indicates the <code><b><i><span style="color:red">ptrace</span></i></b></code> feature that will be used. In order to disable <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall we can change this value to a non existing identifier, for example passing the value <code><b><i><span style="color:red">-1</span></i></b></code>. The following <code><b><i><span style="color:red">radare2</span></i></b></code> code snippet can be used to dynamically manipulate the argument passed to <code><b><i><span style="color:red">ptrace</span></i></b></code> 
</p>

```c

Interceptor.attach(Module.findExportByName(null, 'ptrace'), { 
  onEnter: function (args) { 
    args[0] = ptr(-1) 
  }
})

```

<p style="text-align:justify;">
The following output indicates that the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall has been disabled 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://spawn/usb//re.murphy.ios-challenge-2
INFO: Using safe io mode.
 -- Thank you for using radare2. Have a nice night!
[0x00000000]>
[0x00000000]> :eval Interceptor.attach(Module.findExprtByName*null, 'ptrace'),{onEnter: function (args) { <span style="color:red;"><b>args[0] = ptr(-1)</b></span> }})

{}
[0x00000000]> :dtf ptrace iiii
[0x00000000]> :dc
INFO: resumed spawned process
[0x00000000]> [dtf onLeave][Wed Aug 30 2023 06:50:41 GMT-0700] <span style="color:red;"><b>ptrace@0x1f9970560</b></span> - <span style="color:red;"><b>args: 18446744073709551000</b></span>, 0, 0, 0. <span style="color:red;"><b>Retval: 0xffffffffffffffff</b></span>

</pre>






