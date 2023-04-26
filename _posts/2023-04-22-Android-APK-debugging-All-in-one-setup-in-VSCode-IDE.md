---
layout: single
title: 'Android APK debugging - All in one setup in VSCode IDE'
description: 'This blog post describes the installation and preparation of the needed plugins in oder to debug Android APK files using VSCode IDE'
date: 2023-04-22
classes: wide
comments: false
excerpt: "This blog post explains how to debug an APK file using tools such as VScode, APKLab and adelphes"

header:
  teaser: /assets/images/2023/04/debugging.png
  overlay_image: /assets/images/2023/04/debugging.png
  overlay_filter: rgba(0, 0, 0, 0.7)

tags:
  - VScode
  - apk
  - Android
  - Dynamic source code review
  - Mobile application debugging
  - APKLab
  - Adelphes
---

<p align="justify">
This blog post explains how to use VScode IDE for debugging purposes in collaboration with some of the most trend plugins existing out there regarding Android APK dynamic code analysis. This blog post is mainly for Mobile Application Penetration Testers or Security Engineers who need to debug precompiled APKs in order to detect security issues inside the code, inspecting the code flow dynamically. For the purposes of this lab, the <i>InsecureBankv2.apk</i> will be used. 
</p>

<p align="justify">
First, the <i>InsecureBankv2.apk</i>  will be decompiled using the APKLab plugin. The APKLab plugin can be installed directly to VScode through the use of Extentions as shown at the screenshot below  
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/APKLab.png" width="750" height="400" alt="APKLab"/>

<p align="justify">
As also stated at the Extention's page in VScode, APKLab is a plugin that integrates open-source tools to VScode as those listed below, making the tool very effective because it eliminates the need of running these tools outside the IDE, and as such it gives the code analyst the ability to spend more time in debugging the code rather than in the debugging preparation. 
</p>

- Quark-Engine, 
- Apktool, 
- Jadx, 
- uber-apk-signer, 
- apk-mitm  

<p align="justify">
If you want to read more on this amazing plugin you can read about it in their documentation <a href="https://apklab.surendrajat.xyz/">https://apklab.surendrajat.xyz</a> 
</p>


<p align="justify">
In order to let the APKLab to do the job, we need to open the <i>InsecureBankv2.apk</i> through the VSCode. Then from VSCode Menu, by choosing <code style="background-color: lightgrey; color:black;" style="background-color: lightgrey; color:black;">View->Command Pallete</code>, we can search for the  <code style="background-color: lightgrey; color:black;">APKLab: Open an APK</code> command as shown at the screenshot below :
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/command_palette.png" width="750" height="400" alt="APKLab command palette"/>


<p align="justify">
From the <code style="background-color: lightgrey; color:black;">Open Folder</code> button as seen at the image above, the  <i>InsecureBankv2.apk</i> APK file can be chosen, and from there also several flags can be selected. The most common flags are listed below  
</p>

- <code style="background-color: lightgrey; color:black;">decompile_java</code> ( used for java decompilation ), 
- <code style="background-color: lightgrey; color:black;">--only-main-classes</code> ( used for disassembling  the dex classess  ),
- <code style="background-color: lightgrey; color:black;">--deobf</code> ( used for deobfuscation )

<p align="justify">
The screenshot below shows the options we have when we are about to decompile an APK file using the APKLab plugin in  VSCode  
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/APKLab_flags.png" width="750" height="400" alt="APKLab flags"/>

<p align="justify">
After pressing ok we can see at the output tab of VSCode, the following lines 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
-------------------------------------------------------------------------
Decoding InsecureBankv2.apk into /Users/xenovas/Documents/InsecureBankv21
-------------------------------------------------------------------------
java -jar /Users/xenovas/.apklab/apktool_2.7.0.jar d /Users/xenovas/Documents/InsecureBankv2.apk -o /Users/xenovas/Documents/InsecureBankv21
I: Using Apktool 2.7.0 on InsecureBankv2.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /Users/xenovas/Library/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
Decoding process was successful
-------------------------------------------------------------------------------------
Decompiling InsecureBankv2.apk into /Users/xenovas/Documents/InsecureBankv21/java_src
-------------------------------------------------------------------------------------
/Users/xenovas/.apklab/jadx-1.4.6/bin/jadx --deobf -r -q -v -ds /Users/xenovas/Documents/InsecureBankv21/java_src /Users/xenovas/Documents/InsecureBankv2.apk
Decompiling process was successful

</pre>

<p align="justify">
As seen from the output above, APKLab first uses the <code style="background-color: lightgrey; color:black;">apktool</code> version 2.7.0 in order to decode the android app into smali code and then uses <code style="background-color: lightgrey; color:black;">jadx</code> tool version 1.4.6 in order to perform the actual decompilation of the provided code in java
</p> 

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
jadx --deobf -r -q -v -ds /Users/xenovas/Documents/InsecureBankv21/java_src /Users/xenovas/Documents/InsecureBankv2.apk
</pre>

<p align="justify">
From this point the  <i>InsecureBankv2.apk</i> APK file has been decompiled and the code can be now analysed statically. The following screenshot shows the decompiled code as seen from the Explorer tab of VSCode 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/APKLab_decompiled_APK.png" width="750" height="400" alt="APKLab decompiled APK file"/>


<p align="justify">
Nevertheless, as mentioned before, this lab is about to provide instructions on how to setup an APK debugger on VSCode in order to debug a decompiled <code style="background-color: lightgrey; color:black;">.apk</code> file. Thus, the next steps are about to show how to setup a debugger in order to accomplish this. 
</p>

<p align="justify">
The actual structure of the decompiled APK can be seen below 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
InsecureBankv2
├── AndroidManifest.xml
├── apktool.yml
├── java_src
├── original
├── res
└── smali
</pre>

<p align="justify">
From the tree view above, all the source code is located at the <code style="background-color: lightgrey; color:black;">java_src</code> folder and the decompiled dex classes directly related with the application are also located at the path depicted by the relevant running process on the android device. The <code style="background-color: lightgrey; color:black;">AndroidManifest.xml</code> describes essential information about the application to the Android build tools, the operating system, as well as the Google Play. Furthermore, the main resource files such as XML files used to define attribute animations, or other XML files containing drawables, etc., are placed into the <code style="background-color: lightgrey; color:black;">res</code> folder. Also the <code style="background-color: lightgrey; color:black;"> smali </code> folder contains the decompiled code in smali which is also very intresting location as the smali code can be modified and patched in order to alter the application's behaviour. Finally, the <code style="background-color: lightgrey; color:black;">original</code> folder is the original <code style="background-color: lightgrey; color:black;">AndroidManifest.xml</code> file. The <code style="background-color: lightgrey; color:black;">apktool.yml</code> contains the configuration needed from the APKLab plugin in order to execute the <code style="background-color: lightgrey; color:black;">apktool</code> along with the relevant options provided by the developer. The <code style="background-color: lightgrey; color:black;">apktool</code> can be used to compile or decompile the APK. 
</p>


<p align="justify">
At this point we will rebuild the APK using the <code style="background-color: lightgrey; color:black;">apktool</code> in order to recompile it with debug mode enabled. This could be easily accomplished by using the APKLab plugin. The following screenshot shows the <code style="background-color: lightgrey; color:black;">APKLab: Rebuild the APK</code> option when right clicking on <code style="background-color: lightgrey; color:black;">apktool.yml</code> 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/APK_rebuild_2.png" width="750" height="400" alt="APKLab decompiled APK file"/>

<p align="justify">
The following screenshot shows the  <code style="background-color: lightgrey; color:black;">apktool</code> optional arguments as seen from the command palette on VSCode 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/APK_rebuild.png" width="750" height="400" alt="APKLab decompiled APK file"/>

<p align="justify">
In order to rebuild the <i>InsecureBankv2.apk</i> we run the <code style="background-color: lightgrey; color:black;">apktool</code> by right clicking on the <code style="background-color: lightgrey; color:black;">apktool.yml</code> file from inside the VSCode IDE
</p>


<p align="justify">
After rebuilding the <i>InsecureBankv2.apk</i> the following output should be shown
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
------------------------------------------------------
Rebuilding InsecureBankv2.apk into InsecureBankv2/dist
------------------------------------------------------
java -jar /Users/xenovas/.apklab/apktool_2.7.0.jar b /Users/xenovas/Documents/InsecureBankv2 --use-aapt2 --debug --force-all
I: Using Apktool 2.7.0
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Using aapt2 - setting 'debuggable' attribute to 'true' in AndroidManifest.xml
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: /Users/xenovas/Documents/InsecureBankv2/dist/InsecureBankv2.apk
Rebuilding process was successful
----------------------------------------------
Signing InsecureBankv2/dist/InsecureBankv2.apk
----------------------------------------------
java -jar /Users/xenovas/.apklab/uber-apk-signer-1.2.1.jar -a /Users/xenovas/Documents/InsecureBankv2/dist/InsecureBankv2.apk --allowResign --overwrite
source:
/Users/xenovas/Documents/InsecureBankv2/dist
zipalign location: BUILT_IN 
  /var/folders/wt/dwh1ny455fv8rl8_9j6w24c00000gp/T/uapksigner-11340919931074350973/mac-zipalign-29_0_25123199226427879560.tmp
keystore:
[0] 161a0018 /private/var/folders/wt/dwh1ny455fv8rl8_9j6w24c00000gp/T/temp_56956349993093176_debug.keystore (DEBUG_EMBEDDED)
01. InsecureBankv2.apk
SIGN
file: /Users/xenovas/Documents/InsecureBankv2/dist/InsecureBankv2.apk (3.26 MiB)
checksum: b8221fa10684c0bb40df7b95ea5a5066a8e36a4a359c4b49f19e3c9e02529ac2 (sha256)
- zipalign success
- sign success

  VERIFY
file: /Users/xenovas/Documents/InsecureBankv2/dist/InsecureBankv2.apk (3.3 MiB)
checksum: 660ed86d6086dddf00716718d1ece340f1fb16fa73ffb635f427585ad01bdc52 (sha256)
- zipalign verified

- signature verified [v1, v2, v3]
Subject: CN=Android Debug, OU=Android, O=US, L=US, ST=US, C=US
    SHA256: 1e08a903aef9c3a721510b64ec764d01d3d094eb954161b62544ea8f187b5953 / SHA256withRSA
Expires: Thu Mar 10 22:10:05 EET 2044
[Mon Apr 24 07:21:59 EEST 2023][v1.2.1]
Successfully processed 1 APKs and 0 errors in 1.16 seconds.
Signing process was successful
</pre>

<p align="justify">
As seen above, when rebuilding the <i>InsecureBankv2.apk</i> the APKLab first uses the <code style="background-color: lightgrey; color:black;">apktool_2.7.0.jar</code> with the provided options 
</p>

- <code style="background-color: lightgrey; color:black;">--use-aapt2</code> : AAPT2 (Android Asset Packaging Tool) is a build tool used to compile and package the applications's resources. AAPT2 parses, indexes, and compiles the resources into a binary format that is optimized for the Android platform.
- <code style="background-color: lightgrey; color:black;">--debug</code> : Sets android:debuggable to "true" in the APK's compiled manifest
- <code style="background-color: lightgrey; color:black;">--force-all</code> : Overwrites existing files during build, reassembling the resources.arsc file and dex file(s)


<p align="justify">
Then, after rebuilding the <i>InsecureBankv2.apk</i>, as also shown at the output above, the <a href="https://github.com/patrickfav/uber-apk-signer/releases/download/v1.2.1/uber-apk-signer-1.2.1.jar"><code style="background-color: lightgrey; color:black;">uber-apk-signer-1.2.1.jar</code></a>  used by the APKLab in order to resign the APK. Android requires that all APKs be digitally signed with a certificate before they are installed on a device or updated.
</p>


<p align="justify">
At this point, and when the rebuilding and resigning process finish, a new folder should appear at the treeview of the decompiled application which contains the updated <i>InsecureBankv2.apk</i>  as seen below. 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
InsecureBankv2/dist
└── InsecureBankv2.apk
</pre>

<p align="justify">
The newly created APK should be easily installed inside an android emulator or an android device. For the purposes of this lab the AVD manager VSCode plugin will be used in order to install and create the emulator. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/AVD_Manager_1.png" width="750" height="500" alt="AVD Manager"/>

<p align="justify">
Ofcourse other emulators should also work such as genymotion, but as mentioned, this lab describes the "All in one setup" in VSCode. Moreover, because this lab is focused mainly on the debuging setup we will not go into great details of how to install and configure the virtual devices and Android SDK through the AVD Manager plugin. Nevertheless, the following screenshot shows a preview regarding the AVD Manager setup as seen at the output tab on VSCode 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/AVD_Manager.png" width="750" height="400" alt="AVD Manager"/>

<p align="justify">
In sort, the following configuration / installations should be performed in order to use the AVD Manager 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
SDK Command-Line Tools   
SDK Build Tools        
SDK Platform Tools       
Emulator 
</pre>

<p align="justify">
From the SDK tools panel on AVD Manager plugin, the SDK platform tools version 34.0.1 will be installed, and then from the SDK platforms panel, the Android 11 (R) image with x86_64 ABI and Android SDK platform 30 will also be installed. Moreover, using the SDK tools we will install the android emulator version 32.1.12. Then we will start the emulator as follows 
</p>


<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
cd < Android folder > / emulator
./emulator -writable-system -avd < emulator name >
</pre>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/emulator.png" width="350" height="600" alt="Android Emulator"/>


<p align="justify">
Furthermore, the <a href="https://github.com/adelphes/android-dev-ext">adelphes android debugger</a> plugin will be also be installed in VSCode IDE. This plugin allows developers to install, launch and debug Android applications from within the VSCode environment.
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/adelphes.png" width="750" height="500" alt="Android Emulator"/>

<p align="justify">
From VSCode IDE on the menu bar on the left we will select the "Run and Debug" button. From there, the "Add Configuration" option will be selected listed at the dropdown menu. Then, there will be two options to select regarding the Android configuration. The first should be the  <code style="background-color: lightgrey; color:black;">Android: Attach to Process</code> and the second should be the <code style="background-color: lightgrey; color:black;">Android: Launch Application</code>. 
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/Run_and_Debug.png" width="750" height="500" alt="Android Emulator"/>

<p align="justify">
We can choose both and after some modifications the  <code style="background-color: lightgrey; color:black;">launch.json</code> file should as be as follows. 
</p>


<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "android",
            "request": "launch",
            "name": "Android launch",
            "appSrcRoot": "${workspaceRoot}",
            "apkFile": "${workspaceRoot}/dist/InsecureBankv2.apk",
            "adbPort": 5037
        },
        {
            "type": "android",
            "request": "attach",
            "name": "Android attach",
            "appSrcRoot": "${workspaceRoot}",
            "adbPort": 5037,
            "processId": "${command:PickAndroidProcess}"
        }
    ]
}
</pre>

<p align="justify">
After we choose the <code style="background-color: lightgrey; color:black;">Android: Launch Application</code> from the dropdown menu, the application will automatically be installed inside the android emulator. Nevertheless, other installation options could be used such as using <code style="background-color: lightgrey; color:black;">adb</code> command or just drag and drop the APK into the emulator. The following screen will be shown at the emulator while running the application through VSCode IDE in debug mode. 
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/first_run_insecurebank.png" width="350" height="600" alt="Android Emulator"/>

<p align="justify">
Now, choose continue and then the following screen should be shown
</p>


<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/Waiting_for_debugger.png" width="350" height="600" alt="Android Emulator"/>

<p align="justify">
Now restart the debugger and after a while the application's login screen will show up. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/login.png" width="350" height="600" alt="Android Emulator"/>


<p align="justify">
At this point we should be able to setup our breakpoins into the application but before we do this, we should close everything in VSCode including the debugger and then we will change the application's folder name into <code style="background-color: lightgrey; color:black;">source</code>. Then we will do the same at the <code style="background-color: lightgrey; color:black;">java_src</code> folder and we will rename it to <code style="background-color: lightgrey; color:black;">src</code>. Afterwards, the new structure of the decompiled application should be as follows 
</p>


<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
source
├── AndroidManifest.xml
├── apktool.yml
├── build
├── dist
├── original
├── res
├── smali
└── src
</pre>

<p align="justify">
Afterwards, we will start a new instance of VSCode and we will open the <code style="background-color: lightgrey; color:black;">source</code> folder using the following command 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
code a source
</pre>

<p align="justify">
From the emulator we will start the InsecureBankV2 application and from the <code style="background-color: lightgrey; color:black;">Run and Debug</code> in VSCode we will choose the <code style="background-color: lightgrey; color:black;">Android attach</code> option from the dropdown menu in order to attach to a running process of InsecureBankV2. 
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/android_attach.png" width="750" height="300" alt="Android Emulator"/>


<p align="justify">
Now that we know the process we want to debug we will also check into the relevant folder as seen at the structure below for code related with the login functionality in order to put a breakpoint inside a function of our choice 
</p>

<pre style=" color: white; background: #000000; border: 1px solid #ddd;border-left: 3px solid #f36d33;page-break-inside: avoid;font-family: Courier New; font-size: 15px; line-height: 1.6; margin-bottom: 1.6em; max-width: 100%; padding: 1em 1.5em; display: block; white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;">
source/src/com/android/insecurebankv2
├── BuildConfig.java
├── C0238R.java
├── ChangePassword.java
├── CryptoClass.java
├── DoLogin.java
├── DoTransfer.java
├── FilePrefActivity.java
├── LoginActivity.java
├── MyBroadCastReceiver.java
├── MyWebViewClient.java
├── PostLogin.java
├── TrackUserContentProvider.java
├── ViewStatement.java
└── WrongLogin.java
</pre>

<p align="justify">
As seen above there are four <code style="background-color: lightgrey; color:black;">.java</code> files that are closely related with the Login functionality as their names suggest, and so we can examine their code further to check for issue. For the purposes of this demonstration we will put a breakpoint into the <code style="background-color: lightgrey; color:black;">DoLogin.java</code> file at the <code style="background-color: lightgrey; color:black;">postData()</code> function at line 101. If we now put a username and password of our choice and press the login button we will have our hit! Now we can step into the code and check the values of the variables at the left pane on VSCode IDE.  
</p>

<img style="display: block;margin-left: auto;margin-right: auto;border: 1px solid red;" src="https://xen0vas.github.io/assets/images/2023/04/breakpoint.png" width="750" height="500" alt="Android Emulator"/>


<p align="justify">
Also as seen above, at the left pane of the VSCode IDE we have the variables, the call stack as well as the breakpoints listed, so we can examine the values, the function calls and the locations of our breakpoints into the code base. Thats it for now and i wish you happy bug hunting ! 
</p>
