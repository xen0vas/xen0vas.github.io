---
layout: single
title: 'Win32 reverse shellcode - pt .2 - locating the Export Directory Table'
description: 'This blog post shows how to locate the Export Directory Table from the PE file structure '
date: 2021-07-20
classes: wide
comments: false
header:
  teaser: /assets/images/avatar.jpg
tags:
  - WinDbg
  - Win32 assembly
  - Exploit Development
  - Windows API
  - PE file structure
  - Export Directory Table 
--- 

<p align="justify">
This article focuses on how to locate the Export Directory Table from the PE file structure. This is the second part of a blog series that focuses on how to create a custom Win32 reverse shellcode. 
<br><br>
The first part can be found at the following link 
</p>

* [Win32 reverse shellcode - pt .1 - Locating the kernelbase.dll base address](https://xen0vas.github.io/Win32-Reverse-Shell-Shellcode-part-1-Locating-the-kernelbase-address)

<p align="justify">
According to Microsoft Docs, 
<br>

<blockquote class="">
<p align="justify">
<i>The export symbol information begins with the export directory table, which describes the remainder of the export symbol information. The export directory table contains address information that is used to resolve imports to the entry points within this image. Following, the export address table contains the address of exported entry points and exported data and absolutes. An ordinal number is used as an index into the export address table. If the address specified is not within the export section (as defined by the address and length that are indicated in the optional header), the field is an export RVA, which is an actual address in code or data. Otherwise, the field is a forwarder RVA, which names a symbol in another DLL.</i>
</p>
</blockquote>
</p>

<hr>
<b><span style="color:green;font-size:26px">Search for the Export Directory Table</span></b>

<p align="justify">
From the previous post <a href="https://xen0vas.github.io/Win32-Reverse-Shell-Shellcode-part-1-Locating-the-kernelbase-address/">[pt .1]</a>, we have accomplished to locate the <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> base address. Now that we have the <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> address, we need to parse the PE file structure to find the offset of the export directory table. It is worth to mention here that we will not proceed further in details about the PE file structure, but the following screenshot can provide useful information about the format of the PE file structure.
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2021/07/pe.png" alt="PE File Structure Format"/>

<p align="justify">
The image above has been taken from the following blog post which explains the PE format in more detail. 
</p>

* [PE File Format](https://dandylife.net/blog/archives/388)

<p align="justify">
Before moving further, we need to locate the exact offset of the <code  style="background-color: lightgrey; color:black;"><b>e_lfanew</b></code>. The <code  style="background-color: lightgrey; color:black;"><b>e_lfanew</b></code> field is a 4-byte offset into the file where the PE file header is located. It is necessary to use this offset to locate the PE header in the file. In WinDbg we run the <code  style="background-color: lightgrey; color:black;">dt -n _IMAGE_DOS_HEADER</code> as follows
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dt -n _IMAGE_DOS_HEADER
ntdll!_IMAGE_DOS_HEADER
   +0x000 e_magic          : Uint2B
   +0x002 e_cblp           : Uint2B
   +0x004 e_cp             : Uint2B
   +0x006 e_crlc           : Uint2B
   +0x008 e_cparhdr        : Uint2B
   +0x00a e_minalloc       : Uint2B
   +0x00c e_maxalloc       : Uint2B
   +0x00e e_ss             : Uint2B
   +0x010 e_sp             : Uint2B
   +0x012 e_csum           : Uint2B
   +0x014 e_ip             : Uint2B
   +0x016 e_cs             : Uint2B
   +0x018 e_lfarlc         : Uint2B
   +0x01a e_ovno           : Uint2B
   +0x01c e_res            : [4] Uint2B
   +0x024 e_oemid          : Uint2B
   +0x026 e_oeminfo        : Uint2B
   +0x028 e_res2           : [10] Uint2B
   <span style="color:#cd0000;"><b>+0x03c e_lfanew         : Int4B</b></span>
</pre>

<p align="justify">
As we see above, the <code  style="background-color: lightgrey; color:black;"><b>e_lfanew</b></code> exists at offset <code  style="background-color: lightgrey; color:black;"><b>0x03c</b></code>. According to <a href="https://blog.kowalczyk.info/articles/pefileformat.html">[ this ]</a> blog ,the MS-DOS header occupies the first 64 bytes of the PE file. A structure representing its content is described below
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
typedef struct _IMAGE_DOS_HEADER { 
    USHORT e_magic;         
    USHORT e_cblp;          
    USHORT e_cp;            
    USHORT e_crlc;          
    USHORT e_cparhdr;       
    USHORT e_minalloc;      
    USHORT e_maxalloc;      
    USHORT e_ss;            
    USHORT e_sp;            
    USHORT e_csum;          
    USHORT e_ip;            
    USHORT e_cs;            
    USHORT e_lfarlc;        
    USHORT e_ovno;          
    USHORT e_res[4];        
    USHORT e_oemid;         
    USHORT e_oeminfo;       
    USHORT e_res2[10];      
    LONG   e_lfanew;        
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
</pre>

<p align="justify">
Now that we know the location of the PE header, we will move further to locate the offset of the Export Directory Table from the <code  style="background-color: lightgrey; color:black;"><b>_IMAGE_EXPORT_DIRECTORY</b></code> structure. First we will locate the base address of the  <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> module 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> lm  
start    end        module name
000a0000 000bf000   testasm  C (private pdb symbols)  C:\symbols\testasm\testasm.pdb
712c0000 71434000   ucrtbased   (deferred)             
71440000 7145b000   VCRUNTIME140D   (deferred)             
760a0000 76190000   KERNEL32   (deferred)             
<span style="color:#cd0000;"><b>76190000</b></span> 763a3000   KERNELBASE   (pdb symbols)          c:\symbols\wkernelbase.pdb\4FB470EF91F049226E7209E0E1ADD6791\wkernelbase.pdb
77630000 777d2000   ntdll      (pdb symbols)          c:\symbols\wntdll.pdb\DBC8C8F74C0E3696E951B77F0BB8569F1\wntdll.pdb
</pre>

<p align="justify">
At this point we will use the base address of <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> module marked in red above in order to find the offset of the Export Directory Table for the specific DLL 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !dh 76190000 -f

File Type: DLL
FILE HEADER VALUES
     14C machine (i386)
       6 number of sections
AE908B72 time date stamp
       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
    2102 characteristics
            Executable
            32 bit word machine
            DLL

OPTIONAL HEADER VALUES
     10B magic #
   14.20 linker version
  1D5E00 size of code
   39000 size of initialized data
       0 size of uninitialized data
  114030 address of entry point
    1000 base of code
         ----- new -----
76190000 image base
    1000 section alignment
     200 file alignment
       3 subsystem (Windows CUI)
   10.00 operating system version
   10.00 image version
   10.00 subsystem version
  213000 size of image
     400 size of headers
  2237E3 checksum
00040000 size of stack reserve
00001000 size of stack commit
00100000 size of heap reserve
00001000 size of heap commit
    4140  DLL characteristics
            Dynamic base
            NX compatible
            Guard
  <span style="color:#cd0000;"><b>1C8030 [    EDC0] address [size] of Export Directory</b></span>
  1DBAF4 [      3C] address [size] of Import Directory
  1E2000 [     548] address [size] of Resource Directory
       0 [       0] address [size] of Exception Directory
  20CE00 [    6BF0] address [size] of Security Directory
  1E3000 [   2F998] address [size] of Base Relocation Directory
   81860 [      70] address [size] of Debug Directory
       0 [       0] address [size] of Description Directory
       0 [       0] address [size] of Special Directory
       0 [       0] address [size] of Thread Storage Directory
    11C0 [      AC] address [size] of Load Configuration Directory
       0 [       0] address [size] of Bound Import Directory
  1DB000 [     AE8] address [size] of Import Address Table Directory
  1C6020 [     480] address [size] of Delay Import Directory
       0 [       0] address [size] of COR20 Header Directory
       0 [       0] address [size] of Reserved Directory

</pre>

<p align="justify">
As we see above, and if we go down the structure, we will see ( highlighted in red above ), that the Export Directory exists at offset <code  style="background-color: lightgrey; color:black;"><b>1C8030</b></code> from the <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> base address. So, according to this information, we are able to locate all the values of the arguments passed to the <code  style="background-color: lightgrey; color:black;"><b>IMAGE_EXPORT_DIRECTORY</b></code> as seen below highlighted in red. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dd 76190000+1C8030
76358030  <span style="color:#cd0000;"><b>00000000 ae908b72 00000000 001cca86</b></span>
76358040  <span style="color:#cd0000;"><b>00000001 0000076b 0000076b 001c8058</b></span>
76358050  <span style="color:#cd0000;"><b>001c9e04 001cbbb0</b></span> 00183ee0 001216a0
76358060  00114e40 001ccaeb 00128350 0011ec40
76358070  001dbaf0 00128010 001ac010 00127770
76358080  001ac0b0 001ac160 001ac1d0 001ac290
76358090  001ccc2b 001ccc61 001779e0 00124f40
763580a0  00123720 000fd490 001ac350 001ac3a0
</pre>


<p align="justify">
And all the above information can be mapped using the <code  style="background-color: lightgrey; color:black;"><b>IMAGE_EXPORT_DIRECTORY</b></code> structure as seen below 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 public struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;       <span style="color:#cd0000;"><b>// 00000000</b></span>
        public UInt32 TimeDateStamp;         <span style="color:#cd0000;"><b>// ae908b72</b></span>
        public UInt16 MajorVersion;          <span style="color:#cd0000;"><b>// 0000</b></span>
        public UInt16 MinorVersion;          <span style="color:#cd0000;"><b>// 0000</b></span>
        public UInt32 Name;                  <span style="color:#cd0000;"><b>// 001cca86</b></span>
        public UInt32 Base;                  <span style="color:#cd0000;"><b>// 00000001</b></span>
        public UInt32 NumberOfFunctions;     <span style="color:#cd0000;"><b>// 0000076b</b></span>
        public UInt32 NumberOfNames;         <span style="color:#cd0000;"><b>// 0000076b</b></span>
        public UInt32 AddressOfFunctions;    <span style="color:#cd0000;"><b>// 001c8058 </b></span>
        public UInt32 AddressOfNames;        <span style="color:#cd0000;"><b>// 001c9e04</b></span>
        public UInt32 AddressOfNameOrdinals; <span style="color:#cd0000;"><b>// 001cbbb0</b></span>
    }
</pre>

<p align="justify">
At this point we are most interested at the following structure fields, <code  style="background-color: lightgrey; color:black;"><b>AddressOfFunctions</b></code>, <code  style="background-color: lightgrey; color:black;"><b>AddressOfNames</b></code> and <code  style="background-color: lightgrey; color:black;"><b>AddressOfNameOrdinals</b></code>
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
MOV EDX,DWORD PTR DS:[EBX+3C] ; EDX = DOS->e_lfanew
ADD EDX,EBX                   ; EDX = PE Header
MOV EDX,DWORD PTR DS:[EDX+78] ; EDX = Offset export table
ADD EDX,EBX                   ; EDX = Export table
MOV ESI,DWORD PTR DS:[EDX+20] ; ESI = Offset names table
ADD ESI,EBX                   ; ESI = Names table
XOR ECX,ECX                   ; EXC = 0
</pre>

<p align="justify">
At the first line we will move the pointer to <code  style="background-color: lightgrey; color:black;"><b>e_lfanew</b></code> to the <code  style="background-color: lightgrey; color:black;">edx</code> register at offset <code  style="background-color: lightgrey; color:black;">0x3C</code>, because the size of the <b>MS-DOS</b> header is <code  style="background-color: lightgrey; color:black;">0x40</code> bytes and the last 4 bytes are the <code  style="background-color: lightgrey; color:black;"><b>e_lfanew</b></code> pointer. At the second line we add the value in <code  style="background-color: lightgrey; color:black;">edx</code> to the base address, because the pointer is relative to the base address.
<br><br>
At the third line, the offset <code  style="background-color: lightgrey; color:black;">0x78</code> of the PE header holds the <code  style="background-color: lightgrey; color:black;"><b>DataDirectory</b></code> for the exports. We know this because the size of all PE headers (<code  style="background-color: lightgrey; color:black;"><b>Signature</b></code>, <code  style="background-color: lightgrey; color:black;"><b>FileHeader</b></code> and <code  style="background-color: lightgrey; color:black;"><b>OptionalHeader</b></code>) before the <code  style="background-color: lightgrey; color:black;"><b>DataDirectory</b></code> is exactly <code  style="background-color: lightgrey; color:black;">0x78</code> bytes and the export is the first entry in the <code  style="background-color: lightgrey; color:black;"><b>DataDirectory</b></code> table. At the fourth line, we add this value to the <code  style="background-color: lightgrey; color:black;">edx</code> register and after that we should be placed on the export table of the <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code>.
</p>

<p align="justify">
At the fifth line, in the <code  style="background-color: lightgrey; color:black;"><b>IMAGE_EXPORT_DIRECTORY</b></code> structure, at the offset <code  style="background-color: lightgrey; color:black;">0x20</code>, we can find the pointer to the <code  style="background-color: lightgrey; color:black;"><b>AddressOfNames</b></code>, and from there we can get the exported function names. This is required because we try to find the function by its name even if it is  possible using some other methods. Furthermore, we will save the pointer in the <code  style="background-color: lightgrey; color:black;">esi</code> register and set <code  style="background-color: lightgrey; color:black;">ecx</code> register to 0.
</p>

<p align="justify">
We are now located at the <code  style="background-color: lightgrey; color:black;"><b>AddressOfNames</b></code>, an array of pointers ( relative to the image base address, which is the address where <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> is loaded into memory ). So each 4 bytes will represent a pointer to a function name. Moreover, we can find the function name, and the function name ordinal ( the <code  style="background-color: lightgrey; color:black;"><b>number</b></code> of the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function ) as shown below:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
GetFunction: 

INC ECX                            ; increment counter 
LODSD                              ; Get name offset
ADD EAX,EBX                        ; Get function name
CMP dword [EAX], 0x50746547        ; "PteG"
JNZ SHORT GetFunction              ; jump to GetFunction label if not "GetP"
CMP dword [EAX + 0x4], 0x41636F72  ; "Acor" 
JNZ SHORT GetFunction              ; jump to GetFunction label if not "rocA"
CMP dword [EAX + 0x8],0x65726464   ; "erdd"
JNZ SHORT GetFunction              ; jump to GetFunction label if not "ddre"
</pre>

<p align="justify">
First we will increment <code  style="background-color: lightgrey; color:black;">ecx</code> register, which is the counter of the functions and the function ordinal number. Next we will use the <code  style="background-color: lightgrey; color:black;">esi</code> register as the pointer to the first function name. The <code  style="background-color: lightgrey; color:black;">lodsd</code> instruction will load in <code  style="background-color: lightgrey; color:black;">eax</code> the offset to the function name and then the value in <code  style="background-color: lightgrey; color:black;">eax</code> will be added to the <code  style="background-color: lightgrey; color:black;">ebx</code> ( <code  style="background-color: lightgrey; color:black;"><b>kernelbase</b></code> base address ) in order to find the correct pointer. Note that the <code  style="background-color: lightgrey; color:black;">lodsd</code> instruction will also increment the <code  style="background-color: lightgrey; color:black;">esi</code> register value by 4. This helps us because we do not have to increment it manually, we just need to call again <code  style="background-color: lightgrey; color:black;">lodsd</code> in order to get the next pointer which points to the next module.
</p>

<p align="justify">
Furthermore, the correct pointer to the exported function name has been loaded in the <code  style="background-color: lightgrey; color:black;">eax</code> register. Now we need to check if the exported function name is the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code>. For that reason we compare the exported function name with <code  style="background-color: lightgrey; color:black;">0x50746547</code>. This value is actually <code  style="background-color: lightgrey; color:black;">50 74 65 47</code> in hex, which in little endian means <b>"PteG"</b> in ascii char format. So, we compare if the first 4 bytes of the current function name are <b>"GetP"</b>. If they are not, <code  style="background-color: lightgrey; color:black;">jnz</code> instruction will jump again at our label <code  style="background-color: lightgrey; color:black;">GetFunction</code> and then will continue with the next function name. If it is, we will also check the next 4 bytes, which must be <b>"Acor"</b> and the next 4 bytes <b>"erdd"</b> until to be sure we do not find other function that starts with <b>"GetP"</b>.
</p>

<p align="justify">
At this point we have only found the ordinal of the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function. We will use the ordinal in order to find the actual address of the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function:
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 14px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
MOV ESI,DWORD PTR DS:[EDX+24]     ; ESI = Offset ordinals
ADD ESI,EBX                       ; ESI = Ordinals table
MOV CX,WORD PTR DS:[ESI+ECX*2]    ; CX = Number of function
DEC ECX                           ; Decrement the ordinal 
MOV ESI,DWORD PTR DS:[EDX+1C]     ; ESI = Offset address table
ADD ESI,EBX                       ; ESI = Address table
MOV EDX,DWORD PTR DS:[ESI+ECX*4]  ; EDX = Pointer(offset)
ADD EDX,EBX                       ; EDX = GetProcAddress
</pre>

<p align="justify">
At the first line above, in <code  style="background-color: lightgrey; color:black;">edx</code> we have a pointer to the <code  style="background-color: lightgrey; color:black;"><b>IMAGE_EXPORT_DIRECTORY</b></code> structure. At offset <code  style="background-color: lightgrey; color:black;">0x24</code> of the structure we can find the <code  style="background-color: lightgrey; color:black;"><b>AddressOfNameOrdinals</b></code> offset. In second line, we add this offset to <code  style="background-color: lightgrey; color:black;">ebx</code> register which is the image base of the <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code> so we get a valid pointer to the name ordinals table.
<br><br>
At the third line, the <code  style="background-color: lightgrey; color:black;">esi</code> register contains the pointer to the name ordinals array. This array contains two bytes. We have the name ordinal byte (index) of <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function in <code  style="background-color: lightgrey; color:black;">ecx</code> register, so this way we can get the function address ordinal (index). This will help us to get the function address. In fourth line we have to decrement the ordinal byte because the name ordinals starts from zero (0).
<br><br>
At the fifth line, at the offset <code  style="background-color: lightgrey; color:black;">0x1c</code> we can find the <code  style="background-color: lightgrey; color:black;"><b>AddressOfFunctions</b></code>, the pointer to the function pointer array. At the sixth line we just add the image base of <code  style="background-color: lightgrey; color:black;"><b>kernelbase.dll</b></code>. Then we will be placed at the beginning of the array.

<br><br>
At seventh line, we have the correct index for the <code  style="background-color: lightgrey; color:black;"><b>AddressOfFunctions</b></code> array in <code  style="background-color: lightgrey; color:black;">ecx</code>. There we have found the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function pointer (relative to the image base) at the <code  style="background-color: lightgrey; color:black;">ecx</code> location. Furthermore, we use <code  style="background-color: lightgrey; color:black;">ecx * 4</code> because each pointer has 4 bytes and <code  style="background-color: lightgrey; color:black;">esi</code> points to the beginning of the array. In eighth line, we add the image base, so in the <code  style="background-color: lightgrey; color:black;">edx</code> register we will have the pointer to the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function.
</p>

<p align="justify">
At this point we can see the full implementation we did so far from the previous blog posts until now 

</p>

```c
#include <windows.h>

int main(int argc, char* argv[])
{
    LoadLibrary("user32.dll");
    _asm
    {
        // Locate Kernelbase.dll address
        XOR ECX, ECX              // zero out ECX
        MOV EAX, FS:[ecx + 0x30]  // EAX = PEB
        MOV EAX, [EAX + 0x0c]     // EAX = PEB->Ldr
        MOV ESI, [EAX + 0x14]     // ESI = PEB->Ldr.InMemoryOrderModuleList
        LODSD                     // memory address of the second list entry structure
        XCHG EAX, ESI             // EAX = ESI , ESI = EAX 
        LODSD                     // memory address of the third list entry structure
        XCHG EAX, ESI             // EAX = ESI , ESI = EAX 
        LODSD                     // memory address of the fourth list entry structure
        MOV EBX, [EAX + 0x10]     // EBX = Base address


        // Export Table 
        MOV EDX, DWORD PTR DS : [EBX + 0x3C]    //EDX = DOS->e_lfanew
        ADD EDX, EBX                            //EDX = PE Header
        MOV EDX, DWORD PTR DS : [EDX + 0x78]    //EDX = Offset export table
        ADD EDX, EBX                            //EDX = Export table
        MOV ESI, DWORD PTR DS : [EDX + 0x20]    //ESI = Offset names table
        ADD ESI, EBX                            //ESI = Names table
        XOR ECX, ECX                            //EXC = 0

        GetFunction :

        INC ECX; increment counter
        LODSD                               //Get name offset
        ADD EAX, EBX                        //Get function name
        CMP[EAX], 0x50746547                //"PteG"
        JNZ SHORT GetFunction               //jump to GetFunction label if not "GetP"
        CMP[EAX + 0x4], 0x41636F72          //"rocA"
        JNZ SHORT GetFunction               //jump to GetFunction label if not "rocA"
        CMP[EAX + 0x8], 0x65726464          //"ddre"
        JNZ SHORT GetFunction               //jump to GetFunction label if not "ddre"

        MOV ESI, DWORD PTR DS : [EDX + 0x24]    //ESI = Offset ordinals
        ADD ESI, EBX                            //ESI = Ordinals table
        MOV CX, WORD PTR DS : [ESI + ECX * 2]   //CX = Number of function
        DEC ECX                                 //Decrement the ordinal
        MOV ESI, DWORD PTR DS : [EDX + 0x1C]    //ESI = Offset address table
        ADD ESI, EBX                            //ESI = Address table
        MOV EDX, DWORD PTR DS : [ESI + ECX * 4] //EDX = Pointer(offset)
        ADD EDX, EBX                            //EDX = GetProcAddress

        // Get the Address of LoadLibraryA function 
        XOR ECX, ECX                        //ECX = 0
        PUSH EBX                            //Kernel32 base address
        PUSH EDX                            //GetProcAddress
        PUSH ECX                            //0
        PUSH 0x41797261                     //"Ayra"
        PUSH 0x7262694C                     //"rbiL"
        PUSH 0x64616F4C                     //"daoL"
        PUSH ESP                            //"LoadLibrary"
        PUSH EBX                            //Kernel32 base address
        MOV  ESI, EBX                       //save the kernel32 address in esi for later
        CALL EDX                            //GetProcAddress(LoadLibraryA)
    }
    return 0;
}

```

<p align="justify">
Furthermore, if we load the <code  style="background-color: lightgrey; color:black;">testasm.exe</code> in Windbg debugger, we will see that after the last instruction <code  style="background-color: lightgrey; color:black;">CALL EDX</code> executed, the <code  style="background-color: lightgrey; color:black;">eax</code> register will finally hold the return value from the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function, which will be the address of the <code  style="background-color: lightgrey; color:black;">LoadLobraryA</code> function. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2021/07/WinDbg-EAX-LoadLibraryA.png" alt="WinDbg debugging"  />

<p align="justify">
This was the second part of the <i>custom win32 reverse tcp shellcode development</i> series. At this second part, we have achieved to be in a position to use the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function from <code  style="background-color: lightgrey; color:black;">Kernel32.dll</code> library. In conclusion, after reading this post, we understand that we are at the point where we can use the <code  style="background-color: lightgrey; color:black;">GetProcAddress</code> function, and this is a crucial part before we continue with the reverse tcp shellcode construction, as we will see in a later blog post. What is  important here, is that we are now able to find the address of  <code  style="background-color: lightgrey; color:black;">LoadLibraryA</code> function, which can help us loading other libraries where we can further use their functions. At the thirt part of this <i>custom win32 reverse tcp shellcode development</i> series, we will be focusing on the rest of the construction of the reverse tcp shellcode. 
</p>


