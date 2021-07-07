---
layout: single
title: 'win32 reverse tcp shellcode - pt .1 - Locating the kernel32.dll base address'
description: 'This blog post shows how to locate the kernel32.dll base address using winDbg debugger and x86 assembly language'
date: 2021-07-07
classes: wide
comments: false
header:
  teaser: /assets/images/avatar.jpg
tags:
  - WinDbg
  - kernel32 base address
  - Windows API
  - x86 Assembly
  - Visual Studio
  - PEB
  - TEB
  - Windows Internals 
--- 

<p align="justify">
This article focuses on how to locate the base address of the kernel32.dll module. This is the first part of a series of blog posts focusing on how to create a custom win32 reverse tcp shellcode. The following blog post inspired me to write this article, which i strongly suggest for further reading 
</p>

* [Introduction to Windows shellcode development – Part 3](https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/)

<p align="justify">
We will first exemine the Thread Environment Block (TEB) structure in order to find the exact location of the Process Environment Block (PEB) structure. Then we will navigate through it to search for the pointer to a <code>PEB_LDR_DATA</code> structure which will then provide information about loaded modules. Moreover, using this Windows internal information will also help us to locate the <b>kernel32.dll</b> base address. In WinDbg we can see the TEB structure using the command <code><b>dt _teb</b></code> as shown below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _teb
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : Ptr32 Void
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : Ptr32 Void
   +0x02c ThreadLocalStoragePointer : Ptr32 Void
   +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
   +0x034 LastErrorValue   : Uint4B
   +0x038 CountOfOwnedCriticalSections : Uint4B
   +0x03c CsrClientThread  : Ptr32 Void
[...SNIP...]
</pre>

<p align="justify">
As we see from the ouput above we have out first information about the offset that the PEB structure is located ( offset <code>0x30</code> ) from the start of the TEB structure. Windows uses the FS register to store the address of the TEB structure
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dg fs
                                  P Si Gr Pr Lo
Sel    Base     Limit     Type    l ze an es ng Flags
---- -------- -------- ---------- - -- -- -- -- --------
0053 0033a000 00000fff Data RW Ac 3 Bg By P  Nl 000004f3
</pre>

<p align="justify">
So, as we see from the output above, the TEB structure is located at the address <code>0033a000</code>. In WinDbg we can see the PEB structure using the command <code><b>!peb</b></code> as shown below
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !peb
PEB at 00337000
    InheritedAddressSpace:    No
    ReadImageFileExecOptions: No
    BeingDebugged:            Yes
    ImageBaseAddress:         00400000
    NtGlobalFlag:             70
    NtGlobalFlag2:            0
    Ldr                       77254d80
    Ldr.Initialized:          Yes
    Ldr.InInitializationOrderModuleList: 007b3830 . 007b3d18
    Ldr.InLoadOrderModuleList:           007b3928 . 007b4c70
    Ldr.InMemoryOrderModuleList:         007b3930 . 007b4c78
            Base TimeStamp                     Module
          400000 4ce63b00 Nov 19 10:53:20 2010 C:\Users\Xenofon\Desktop\vulnserver-master\vulnserver.exe
        77130000 1bdbc4b8 Oct 23 15:52:56 1984 C:\Windows\SYSTEM32\ntdll.dll
        765f0000 7e8f02e1 Apr 14 08:00:01 2037 C:\Windows\System32\KERNEL32.DLL
        75cc0000 C:\Windows\System32\KERNELBASE.dll
        75b20000 4c1230ad Jun 11 14:48:45 2010 C:\Windows\System32\msvcrt.dll
        75ab0000 4fe56754 Jun 23 08:51:00 2012 C:\Windows\System32\WS2_32.DLL
        76530000 C:\Windows\System32\RPCRT4.dll
        62500000 4ce61c00 Nov 19 08:41:04 2010 C:\Users\Xenofon\Desktop\vulnserver-master\essfunc.dll
   [...SNIP...]
</pre>

<p align="justify">
As we see, there is some valuable information available from the command used above regarding the PEB stucture, which can help us significantly, giving us a foothold on how to move further. According to this information we can now check the <code>ldr</code> pointer at <code>0x77254d80</code> to clarify that indeed points to the <code>_PEB_LDR_DATA</code> structure. We can check this by using the command <code>dt _peb @$peb</code> in WinDbg as seen below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _peb @$peb
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y0
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x00400000 Void
   +0x00c Ldr              : 0x77254d80 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x007b1e20 _RTL_USER_PROCESS_PARAMETERS
   +0x014 SubSystemData    : (null) 
   +0x018 ProcessHeap      : 0x007b0000 Void
   +0x01c FastPebLock      : 0x77254b40 _RTL_CRITICAL_SECTION
 [...SNIP...]
</pre>

<p align="justify">
There is indeed the <code>_PEB_LDR_DATA</code> structure located at address <code>0x77254d80</code>, and the pointer of that structure is located at offset <code>0x00c</code>. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> ? poi(@$peb+0xc)
Evaluate expression: 1998933376 = 77254d80
</pre>

<p align="justify">
Furthermore, we will use this address in order to find the exact offset of <code>InMemoryOrderModuleList</code> as seen below 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _PEB_LDR_DATA 0x77254d80
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x7b3928 - 0x7b4c70 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x7b3930 - 0x7b4c78 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x7b3830 - 0x7b3d18 ]
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null)
</pre>

<p align="justify">
Now lets get the <code>InMemoryOrderModuleList</code> adddress since we know the offset ( <code>0x014</code> )
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> ? poi(poi(@$peb+0xc)+0x14)
Evaluate expression: 8075568 = 007b3930
</pre>

<p align="justify">
Following is the <code>_PEB_LDR_DATA</code> structure prototype
</p>

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

At this point we are interested mainly in <code>InMemoryOrderModuleList</code> which according to msdn, is the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an <code>LDR_DATA_TABLE_ENTRY</code> structure. Lets check this out


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr32 Void
   +0x00c InLoadOrderModuleList : _LIST_ENTRY
   <span style="color:#cd0000;"><b>+0x014 InMemoryOrderModuleList : _LIST_ENTRY</b></span>
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY
   +0x024 EntryInProgress  : Ptr32 Void
   +0x028 ShutdownInProgress : UChar
   +0x02c ShutdownThreadId : Ptr32 Void
</pre>

<p align="justify">
As seen above, we realize that the <code>InMemoryOrderModuleList</code> is located at offset <code>0x014</code>. 
</p>

<p align="justify">
At this point lets start constructing our instructions
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
XOR ECX, ECX                  ; zero out ECX
MOV EAX, FS:[ecx + 0x30]      ; EAX = PEB
</pre>

<p align="justify">
At the first two lines above, the first instruction sets the <code>ecx</code> register to zero and the second instruction uses <code>ecx</code> to avoid null bytes. Lets explain this a bit.. If we use the <code>mov eax,fs:[30]</code> instruction, it will be assembled to the following opcode sequence, <code>64 A1 30 00 00 00</code>, which apparently produces null bytes. In the contrary, if we use the instruction <code>mov eax, fs:[ecx+0x30]</code>, it will be assembled to <code>64 8B 41 30</code>, which does not contain null bytes. 
<br><br>
Below we see this in practice using the <code>msf-nasm</code> tool from metasploit framework.  
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
nasm > MOV EAX, FS:[ecx + 0x30]
00000000  648B4130          mov eax,[fs:ecx+0x30]
nasm > MOV EAX, FS:[0x30]
00000000  64A130000000      mov eax,[fs:0x30]
</pre>

<p align="justify">
At this point we need to move further and find the address of the <code>InMemoryOrderModuleList</code>, and then the pointer to <code>LDR_DATA_TABLE_ENTRY</code> structure, which as said before will help us to find the exact offset of <code>kernel32.dll</code> module and finaly load it into <code>ebx</code> register as we'll see later
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
MOV EAX, [EAX + 0xc]          ; EAX = PEB->Ldr
MOV ESI, [EAX + 0x14]         ; ESI = PEB->Ldr.InMemoryOrderModuleList
</pre>

<p align="justify">
At the first line above, we have the <code>ldr</code> pointer loaded in the <code>eax</code> register. The <code>mov</code> instruction saves the address of the <code>PEB_LDR_DATA</code> structure in <code>eax</code> register. The <code>PEB_LDR_DATA</code> structure is located at the offset <code>0x0C</code> at the <code>PEB</code> structure. Moreover, in case we follow that pointer in the <code>PEB_LDR_DATA</code>, then, at offset <code>0x14</code>  we have the <code>InMemoryOrderModuleList</code>. Here, the first element is a forward link or <code><b>Flink</b></code>, which is a pointer to the next module in the doubled linked list. In addition to this, as we see above, the pointer placed inside the <code>esi</code> register.
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _PEB_LDR_DATA poi(@$peb+0xc)
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x7b3928 - 0x7b4c70 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x7b3930 - 0x7b4c78 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x7b3830 - 0x7b3d18 ]
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null)  
0:000> dx -r1 (*((ntdll!_LIST_ENTRY *)0x77254d94))
(*((ntdll!_LIST_ENTRY *)0x77254d94))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0x7b3930 [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x7b4c78 [Type: _LIST_ENTRY *]
0:000> dx -r1 ((ntdll!_LIST_ENTRY *)0x7b3930)
((ntdll!_LIST_ENTRY *)0x7b3930)                 : 0x7b3930 [Type: _LIST_ENTRY *]
    [+0x000] Flink            : <span style="color:#cd0000;"><b>0x7b3828</b></span> [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x77254d94 [Type: _LIST_ENTRY *]
</pre>

<p align="justify">
Furthermore, we can also move streight to the address that we are interested in using the WinDbg command <code>dt _PEB_LDR_DATA poi(poi(@$peb+0xc)+0x14)</code>
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _PEB_LDR_DATA poi(poi(@$peb+0xc)+0x14)
ntdll!_PEB_LDR_DATA
   +0x000 Length           : 0x7b3828
   +0x004 Initialized      : 0x94 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x0 - 0x400000 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x401130 - 0x7000 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x740072 - 0x7b22e8 ]
   +0x024 EntryInProgress  : 0x001e001c Void
   +0x028 ShutdownInProgress : 0x3e '>'
   +0x02c ShutdownThreadId : 0x800022cc Void

</pre>

<p align="justify">
Now lets verify that the <code>0x7b3828</code> is indeed the address of <code>ntdll.dll</code> module. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _LDR_DATA_TABLE_ENTRY 0x7b3828
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x7b3d10 - 0x7b3930 ]
   <span style="color:#cd0000;"><b>+0x008</b></span> InMemoryOrderLinks : _LIST_ENTRY [ 0x7b40e8 - 0x77254d9c ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x77130000 - 0x0 ]
   +0x018 DllBase          : 0x001a2000 Void
   +0x01c EntryPoint       : 0x003c003a Void
   +0x020 SizeOfImage      : 0x7b3700
   +0x024 FullDllName      : _UNICODE_STRING "ntdll.dll"
   +0x02c BaseDllName      : _UNICODE_STRING <span style="color:#cd0000;"><b>"--- memory read error at address 0x0000ffff ---"</b></span>
   [...SNIP...]
</pre>

<p align="justify">
Well, there is an error above as you can see <code>"--- memory read error at address 0x0000ffff ---"</code>. Thats because the <code>InMemoryOrderLinks</code> is located at offset <code>0x8</code> ( highlighted in red above ). In order to fix this issue we subtract <code>0x8</code> from the address <code>0x7b3828</code>
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _LDR_DATA_TABLE_ENTRY <span style="color:#cd0000;"><b>0x7b3828-8</b></span>
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x7b3d08 - 0x7b3928 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x7b3d10 - 0x7b3930 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x7b40e8 - 0x77254d9c ]
   +0x018 DllBase          : 0x77130000 Void
   +0x01c EntryPoint       : (null) 
   +0x020 SizeOfImage      : 0x1a2000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
   +0x02c BaseDllName      : _UNICODE_STRING "ntdll.dll"
   +0x034 FlagGroup        : [4]  "???"
[...SNIP...]
</pre>

<p align="justify">
We can verify that the address of the <code>ntdll.dll</code> is <code>0x77130000</code> as seen at offset <code>0x18</code> at <code>DllBase</code> above. The <code>lodsd</code> instruction below will follow the pointer specified by the <code>esi</code> register and the results will be placed inside the <code>eax</code> register. In such case the memory address of the second list entry structure will be loaded in <code>eax</code> register.  
</p> 

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
LODSD  ; memory address of the second list entry structure
</pre>

<p align="justify">
Now that we know the address of the <code>ntdll.dll</code> module, we can proceed further in the linked list to find the third list entry structure which will give us the offset of the <code>kernel32.dll</code> module.

In order to do this we will follow the linked list and see where it points next. The <code>lodsd</code> instruction will follow the pointer specified by the <code>esi</code> register and the results will be placed inside the <code>eax</code> register. As we know, after the <code>lodsd</code> instruction assigns the value pointed to the address loaded in <code>esi</code> register into the <code>eax</code> register, then increments <code>esi</code> by 4 (pointing to the next dword) pointing to the next list entry structure. For that reason, before using the <code>lodsd</code> instruction for the second time, we should first use the <code>xchg</code> instruction in order to assign the next pointer to <code>esi</code> register. This means that after executing the <code>lodsd</code> instruction, the address of the third list entry structure, will be placed inside the <code>eax</code> register. Furthermore, inside this list entry structure we can find the offset ( <code>0x18</code> ) which holds the base address of the <code>kernel32.dll</code> module.  
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
XCHG EAX, ESI ; EAX = ESI , ESI = EAX 
LODSD  ; memory address of the third list entry structure
</pre>

<p align="justify">
At this point, we will search for the <code>kernel32.dll</code> base address offset using WinDbg 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt _LDR_DATA_TABLE_ENTRY 0x7b3d10-8
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x7b40d8 - 0x7b3820 ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x7b40e0 - 0x7b3828 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x77254d9c - 0x7b40e8 ]
   <span style="color:#cd0000;"><b>+0x018 DllBase          : 0x765f0000 Void</b></span>
   +0x01c EntryPoint       : 0x7660f5a0 Void
   +0x020 SizeOfImage      : 0xf0000
   +0x024 FullDllName      : _UNICODE_STRING "C:\Windows\System32\KERNEL32.DLL"
   <span style="color:#cd0000;"><b>+0x02c BaseDllName      : _UNICODE_STRING "KERNEL32.DLL"</b></span>
   +0x034 FlagGroup        : [4]  "???"
[...SNIP...]
</pre>

<p align="justify">
As we see above, the <code>BaseDllName</code> holds the <code>kernel32.dll</code> name at offset <code>0x02c</code> and the <code>DllBase</code> holds its address <code>0x765f0000</code> at offset <code>0x18</code>. So in order to gain the <code>kernel32.dll</code> base address, we need to use the following command in WinDbg, as well as to do the appropriate calculations. 
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> ? <span style="color:#cd0000;"><b>0x7b3d10-8+18</b></span>
Evaluate expression: 8076576 = <span style="color:#cd0000;"><b>007b3d20</b></span>
0:000> db 007b3d20
007b3d20  <span style="color:#cd0000;"><b>00 00 5f 76</b></span> a0 f5 60 76-00 00 0f 00 40 00 42 00  .._v..`v....@.B.
007b3d30  10 3e 7b 00 18 00 1a 00-38 3e 7b 00 cc a2 0c 00  .>{.....8>{.....
007b3d40  ff ff 00 00 10 4c 25 77-10 4c 25 77 e1 02 8f 7e  .....L%w.L%w...~
007b3d50  00 00 00 00 00 00 00 00-c8 3d 7b 00 c8 3d 7b 00  .........={..={.
007b3d60  c8 3d 7b 00 00 00 00 00-00 00 00 00 a4 11 13 77  .={............w
007b3d70  80 4e 7b 00 88 38 7b 00-00 00 00 00 2c 51 7b 00  .N{..8{.....,Q{.
007b3d80  4c 41 7b 00 9d 39 7b 00-00 00 5f 76 00 00 00 00  LA{..9{..._v....
007b3d90  6f 9c b5 d5 35 72 d7 01-52 d6 6c 53 04 00 00 00  o...5r..R.lS....
0:000> dt poi(0x007b3d20)
Symbol not found at address <span style="color:#cd0000;"><b>765f0000</b></span>.
</pre>

<p align="justify">
As we see from the output above, the <code>kernel32.dll</code> base address is located at offset <code>0x18 - 0x8 = 0x10 </code>. At this point the following instruction will take place 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
MOV EBX, [EAX + 0x10]   ; EBX = Base address
</pre>

<p align="justify">
From the instruction above, as we saw earlier, using the <code>lodsd</code> instruction, the <code>eax</code> register holds a pointer to the second list entry of the <b>InMemoryOrderLinks</b> stucture. Furthermore, if we add <code>0x10</code> bytes to <code>eax</code> register, we will have the <b>DllBase</b> pointer, which points to the memory address of the <b>kernel32.dll</b> module.
</p>

<p align="justify">
Finally, we will use the following C program in order to test our assembly instructions and check the addresses in the specified registers. In order to test our assembly instructions we will use Visual Studio 
</p>

```c
#include <windows.h>
int main(int argc, char* argv[])
{
   LoadLibrary("user32.dll");
   _asm
   {
      XOR ECX, ECX; zero out ECX
      MOV EAX, FS:[ecx + 0x30]; EAX = PEB
      MOV EAX, [EAX + 0x0c]; EAX = PEB->Ldr
      MOV ESI, [EAX + 0x14]; ESI = PEB->Ldr.InMemoryOrderModuleList
      LODSD ; memory address of the second list entry structure
      XCHG EAX, ESI ; EAX = ESI , ESI = EAX 
      LODSD ; memory address of the third list entry structure
      MOV EBX, [EAX + 0x10]; EBX = Base address
   }
   return 0;
}
```

<p align="justify">
Furthermore, as we see at the screenshot below, the <code>ebx</code> register holds the <code>kernel32.dll</code> base address, so our instructions are working as expected. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2021/07/visual-studio.png" alt="APIMonitor"  />

<p align="justify">
Thats it for now. The second part of the custom win32 reverse tcp shellcode development series will be focusing on how to parse a PE file and find the export table. 
</p>

<p align="justify">
I hope you enjoyed this first part ! 
</p>

