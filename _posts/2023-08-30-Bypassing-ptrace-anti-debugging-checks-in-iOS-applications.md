

---
layout: single
title: 'Bypassing ptrace anti-debugging check in iOS applications'
description: 'This blog post focuses specifically on bypassing ptrace iOS anti-debugging defence. The ptrace syscall lets users control and inspect the targeted application behaviour'
date: 2023-08-30
comments: false
classes: wide
excerpt: "This blog post focuses specifically on bypassing ptrace iOS anti-debugging defence which prevents an iOS mobile application from entering into a debugging state"

header:
  teaser: /assets/images/2023/08/ios/ptraceDisassembly.png
  overlay_image: /assets/images/2023/08/ios/ptraceDisassembly.png
  overlay_filter: rgba(0, 0, 0, 0.7)

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



### Introduction 

<p style="text-align:justify;">
This blog post focuses specifically on bypassing ptrace iOS anti-debugging defence which prevents an iOS mobile application from entering into a debugging state. The ptrace syscall can be found several *nix operating systems. It lets users control and inspect the targeted application behaviour. Also, this blog post covers only one feature of the ptrace syscall, the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></b></i></code>.
</p>


<blockquote class=""><em><b>Disclaimer</b></em> :
</blockquote>
<blockquote><em><b><p style="text-align:justify;">PT_DENY_ATTACH</b>: 
                   This request is the other operation used by the traced
                   process; it allows a process that is not currently being
                   traced to deny future traces by its parent.  All other
                   arguments are ignored.  If the process is currently being
                   traced, it will exit with the exit status of ENOTSUP; oth-erwise, otherwise,
                   erwise, it sets a flag that denies future traces.  An
                   attempt by the parent to trace a process which has set this
                   flag will result in a segmentation violation in the parent.</p></em></blockquote>


<p style="text-align:justify;">
For the purpose of this blog post we will use the <a href="https://github.com/hexploitable/r2con2020_r2frida/blob/master/ios-challenge-2.ipa"><code><b><span style="color:red"><u>ios-challenge-2</u></span></b></code></a> application to showcase the identification of the ptrace antibugging technique as well as to present a way to bypass it. 
---

<br>
<h3>Installing r2frida plugin</h3>
<hr>

<p style="text-align:justify;">
Assuming that <code><b><span style="color:red">radare2</span></b></code> is already installed on the local machine, using the following commands we are also able to install <code><b><span style="color:red">r2frida</span></b></code> plugin. This plugin aims to join the capabilities of static analysis of <code><b><span style="color:red">radare2</span></b></code> and the instrumentation provided by frida. The recommended way to install <code><b><span style="color:red">r2frida</span></b></code> is by using <a href="https://r2wiki.readthedocs.io/en/latest/tools/r2pm/"><code><b><span style="color:red">r2pm</span></b></code></a>
</p>




<p style="text-align:justify;">
The following command will initialize the package control 
</p>

```
 ~/ r2pm init

```

<p style="text-align:justify;">
After the initialization the package manager will have the plugins ready to install. We will run the following command in order to install <code><b><span style="color:red">r2frida</span></b></code> plugin
</p>



<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
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
The succesful execution of the command above will download the plugin from the specified repo and then after building and installing the plugin, the <code><b><span style="color:red">r2frida</span></b></code> will be able to run 
</p>

<p style="text-align:justify;">
The following command shows the installed apps as well as the running apps on the virtual device 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://apps/usb
PID           Name Identifier
-----------------------------
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

<p style="text-align:justify;">
From here we can search the available command using the help command <code><b><span style="color:red">:?</span></b></code>
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x00000000]> :?
r2frida commands are prefixed with `:` (alias for `=!`).
:. script                   Run script
:  frida-expression         Run given expression inside the agent
:/[x][j] <string|hexpairs>  Search hex/string pattern in memory ranges (see search.in=?)
:/v[1248][j] value          Search for a value honoring `e cfg.bigendian` of given width
:/w[j] string               Search wide string
:<space> code..             Evaluate Cycript code
:?                          Show this help
:?e message                 Show message like ?e but from the agent
:?E title message           Show UIAlert dialog with given title and message
:?V                         Show target Frida version
:chcon file                 Change SELinux context (dl might require this)
:d.                         Start the chrome tools debugger
:dbn [addr|-addr]           List set, or delete a breakpoint
:dbnc [addr] [command]      Associate an r2 command to an r2frida breakpoint
:db (<addr>|<sym>)          List or place breakpoint (DEPRECATED)
:db- (<addr>|<sym>)|*       Remove breakpoint(s) (DEPRECATED)
:dc                         Continue breakpoints or resume a spawned process
:dd[j-][fd] ([newfd])       List, dup2 or close filedescriptors (ddj for JSON)
:di[0,1,-1,i,s,v] [addr]    Intercepts and replace return value of address without calling the function
:dif[0,1,-1,i,s] [addr]     Intercepts return value of address after calling the function
:dk ([pid]) [sig]           Send specific signal to specific pid in the remote system
:dkr                        Print the crash report (if the app has crashed)
:dl libname                 Dlopen a library (Android see chcon)
:dl2 libname [main]         Inject library using Frida's >= 8.2 new API
:dlf path                   Load a Framework Bundle (iOS) given its path
:dlf- path                  Unload a Framework Bundle (iOS) given its path
:dm[.|j|*]                  Show memory regions
:dma <size>                 Allocate <size> bytes on the heap, address is returned
:dma- (<addr>...)           Kill the allocations at <addr> (or all of them without param)
:dmad <addr> <size>         Allocate <size> bytes on the heap, copy contents from <addr>
:dmal                       List live heap allocations created with dma[s]
:dmas <string>              Allocate a string initiated with <string> on the heap
:dmaw <string>              Allocate a widechar string initiated with <string> on the heap
:dmh                        List all heap allocated chunks
:dmh*                       Export heap chunks and regions as r2 flags
:dmhj                       List all heap allocated chunks in JSON
:dmhm                       Show which maps are used to allocate heap chunks
:dmm                        List all named squashed maps
:dmp <addr> <size> <perms>  Change page at <address> with <size>, protection <perms> (rwx)
:dp                         Show current pid
:dpt                        Show threads
:dr                         Show thread registers (see dpt)
:dt (<addr>|<sym>) ..       Trace list of addresses or symbols
:dt- (<addr>|<sym>)         Clear trace
:dt-*                       Clear all tracing
:dt.                        Trace at current offset
:dtf <addr> [fmt]           Trace address with format (^ixzO) (see dtf?)
:dth (addr|sym)(x:0 y:1 ..) Define function header (z=str,i=int,v=hex barray,s=barray)
:dtl[-*] [msg]              debug trace log console, useful to .:T*
:dtr <addr> (<regs>...)     Trace register values
:dts[*j] seconds            Trace all threads for given seconds using the stalker
:dtsf[*j] [sym|addr]        Trace address or symbol using the stalker (Frida >= 10.3.13)
:dxc [sym|addr] [args..]    Call the target symbol with given args
:e[?] [a[=b]]               List/get/set config evaluable vars
:env [k[=v]]                Get/set environment variable
:eval code..                Evaluate Javascript code in agent side
:fd[*j] <address>           Inverse symbol resolution
:i                          Show target information
:iE[*] <lib>                Same as is, but only for the export global ones
:iS[*]                      List sections
:iS.                        Show section name of current address
:iSj                        List sections in Json format
:iSS[*]                     List segments
:iSS.                       Show segment name of current address
:iSSj                       List segments in Json format
:ic <class>                 List Objective-C/Android Java classes, or methods of <class>
:ii[*]                      List imports
:il                         List libraries
:ip <protocol>              List Objective-C protocols or methods of <protocol>
:is[*] <lib>                List symbols of lib (local and global ones)
:isa[*] (<lib>) <sym>       Show address of symbol
:j java-expression          Run given expression inside a Java.perform(function(){}) block
:r [r2cmd]                  Run r2 command using r_core_cmd_str API call (use 'dl libr2.so)
:t [swift-module-name]      Show structs, enums, classes and protocols for a module (see swift: prefix)
[0x00000000]>

</pre>

<br>
<h3>Installing r2ghidra plugin</h3>
<hr>

<p style="text-align:justify;">
In order to enhance reverse engineering capabilities provided by <code><b><span style="color:red">radare2</span></b></code> we will integrate the <code><b><span style="color:red">Ghidra</span></b></code> decompiler by installing the <code><b><span style="color:red">r2ghidra</span></b></code> plugin. Using the following command we will install the plugin  
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
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
Furthermore, we should also install SLEIGH disassembler that comes with <code><b><span style="color:red">r2ghidra</span></b></code> using the following command 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
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

----

<br>
<h3>Application dynamic analysis</h3>
<hr>

<p style="text-align:justify;">
After installing and running the application it will exit immediately. The following command will spawn the app which will show the detach reason and the process termination message on the output. Lets see this in practice
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://spawn/usb//re.murphy.ios-challenge-2
INFO: Using safe io mode.
 -- git pull now
[0x00000000]> INFO: DetachReason: FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED
</pre>

<p style="text-align:justify;">
Now lets spawn the application again but this time we will use the <code><b><i><span style="color:red">:dtf</span></i></b></code> command which will trace the address of the ptrace syscall and  will also show the arguments in integer format
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x00000000]> oo
INFO: Using safe io mode.
INFO: resumed spawned process
[0x00000000]> :dtf ptrace ii

true
[0x00000000]> :dc
INFO: resumed spawned process
[0x00000000]> [dtf onLeave][Wed Aug 30 2023 00:57:33 GMT-0700] ptrace@0x1f9970560 - args: 31, 0. Retval: 0x0
INFO: DetachReason: FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED
</pre>

<p style="text-align:justify;">
As we see the application terminated again and from the args value (31) we are able to determine that the feature of the ptrace syscall is the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></b></i></code>.
</p>

<p style="text-align:justify;">
According with  <a href="https://github.com/OWASP/owasp-mastg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md"><code><b><span style="color:red"><u>OWASP-MASTG and iOS Anti-Reversing Defenses</u></span></b></code></a>, the ptrace syscall is not part of the public iOS API. Non-public APIs are prohibited, and the App Store may reject apps that include them. Because of this, ptrace is not directly called in the code; it's called when a ptrace function pointer is obtained via <code><b><i><span style="color:red">dlsym</span></b></i></code>. The following code snippet represents the above logic 
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

<br>
<h3>Application static analysis</h3>
<hr>


<p style="text-align:justify;">
At this point and after we gained all the needed knowledge regarding the ptrace anti-debugging technique, we can move forward to perform a static analysis. 
</p>

<p style="text-align:justify;">
First we will decomplress tha <code><b><span style="color:red">.ipa</span></b></code> file in order to statically examine the application using <code><b><span style="color:red">radare2</span></b></code>
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
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
As we previously saw, the <code><b><i><span style="color:red">ptrace</span></b></i></code> syscall is generally invoked via <code><b><i><span style="color:red">dlsym</span></b></i></code> so we will search for it as follows
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008e44]> axt sym.imp.dlsym
sym.func.100008864 0x100008888 [CALL:--x] bl sym.imp.dlsym
[0x100008e44]>
</pre>


<p style="text-align:justify;">
At this point we will continue using radare2 in order to see the execution flow and to examine the ARM assembly in order to have a view of the checks in a lower level
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008e44]> s sym.func.100008864
[0x100008864]> VV
</pre>

<p style="text-align:justify;">
As we see at the screenshot below we have obtained a lot of information regarding the ptrace implementation. Specifically we see that the ptrace is called by <code><b><i><span style="color:red">Challenge1.viewDidLoad</span></i></b></code> and also we are able to determine the feature of the <code><b><i><span style="color:red">ptrace</span></i></b></code> from the <code><b><i><span style="color:red">0xf1</span></i></b></code> value which is <code><b><i><span style="color:red">31</span></i></b></code> in decimal indicating the <code><b><i><span style="color:red">'PT_DENY_ATTACH'</span></b></i></code> feature. 
</b>

<a href="/Users/xenovas/Documents/TwelveSec/blog/dlsym-ptrace.png">
   <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="/Users/xenovas/Documents/TwelveSec/blog/dlsym-ptrace.png" width="750" height="450" alt="dlsym-ptrace"/>
</a>


<p style="text-align:justify;">
At this point we are able to examine the <code><b><i><span style="color:red">viewDidLoad</span></b></i></code> method as we know that it implements the <code><b><i><span style="color:red">ptrace</span></i></b></code> syscall. 
</b>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008864]> ic Challenge1
class Challenge1
0x100008a4c method Challenge1      viewDidLoad
0x100008abc method Challenge1      jailbreakTest1Tapped:
0x100008b14 method Challenge1      showAlertWithMessage:
0x100008c3c method Challenge1      isJailbroken
[0x100008864]>
</pre>

<p style="text-align:justify;">
We can see that the <code><b><i><span style="color:red">viewDidLoad</span></b></i></code> method is located at <code><b><i><span style="color:red">0x100008a4c</span></b></i></code> address as seen above, so lets further check the validations on radare2 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[0x100008864]> s 0x100008a4c
[0x100008a4c]> VV
</pre>


<a href="/Users/xenovas/Documents/TwelveSec/blog/viewDidLoad-1.png">
   <img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="/Users/xenovas/Documents/TwelveSec/blog/viewDidLoad-1.png" width="750" height="450" alt="viewDidLoad-1"/>
</a>

<br>
<p style="text-align:justify;">
If we examine further we will see that except the ptrace syscall there are other anti-debugging techniques enabled, but as we mentioned earlier at this blog post we will be focusing only to ptrace syscall. 
</p>

<p style="text-align:justify;">
Lets also decompile the code using  <code><b><i><span style="color:red">r2ghidra</span></i></b></code> in order to have a high level view of the viewDidLoad implementation
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
As seen from the decompiled code above, the first check is implemnted using the ptrace ( <code><b><i><span style="color:red">sym.func.100008864</span></i></b></code> ) syscall. At this point we can bypass ptrace syscall using r2frida 
</p>


<br>
<h3>Hooking with r2frida</h3>
<hr>


<p style="text-align:justify;">
As we saw earlier the argument passed to ptrace was the 0xf1 in hex which indicates the ptrace feature that will be used. In order to disable ptrace syscall we can change this value to a non existing identifier, for example passing the value -1. The following radare2 code snippet can be used to dynamically manipulate the argument passed to ptrace 
</p>

```c
Interceptor.attach(Module.findExportByName(null, 'ptrace'), { 
  onEnter: function (args) { 
    args[0] = ptr(-1) 
  }
})
```

<p style="text-align:justify;">
The following radare2 commands are used to disable ptrace syscall dynamically
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 ~/ r2 frida://spawn/usb//re.murphy.ios-challenge-2
INFO: Using safe io mode.
 -- Thank you for using radare2. Have a nice night!
[0x00000000]>
[0x00000000]> :eval Interceptor.attach(Module.findExprtByName*null, 'ptrace'),{onEnter: function (args) { <span style="color:red;">args[0] = ptr(-1)</span> }})

{}
[0x00000000]> :dtf ptrace iiii
[0x00000000]> :dc
INFO: resumed spawned process
[0x00000000]> [dtf onLeave][Wed Aug 30 2023 06:50:41 GMT-0700] ptrace@0x1f9970560 - <span style="color:red;">args: 18446744073709551000</span>, 0, 0, 0. <span style="color:red;">Retval: 0xffffffffffffffff</span>

</pre>






