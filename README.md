# Sysprep Volatile Environment LPE

**Important: This exploit is from 2017 and not the known Sysprep exploit found in Windows 7!**

| Exploit Information |                                   |
|:------------------- |:--------------------------------- |
| Publish Date        | 28.06.2017                        |
| Patched             | Windows 10 RS3 (16299)            |
| Tested on           | Windows 8-10, x86 and x64         |

## Description

There is a known UAC bypass vulnerability that was first discovered in Windows 7 Release Candidate. Due to sysprep.exe being in a sub directory, DLL hijacking was possible. In Windows 8 and above, this issue is fixed, Windows 7 is not patched to this day.

So much for the past, moving on. Sysprep was patched by loading some DLL's from a specific directory instead.

Let's look at Sysprep's manifest:

```xml
﻿<!--
    Specifically load these DLLs from the specified path. This
    is done as a defence-in-depth approach to closing a known UAC
    exploit related to sysprep.exe being auto-elevated. The list
    need not contain KnownDlls since those are always loaded
    by the loader from the system directory.
-->
<file
    loadFrom="%systemroot%\system32\actionqueue.dll"
    name="actionqueue.dll"
    />
[...]
```

So, now all vulnerable DLL's are loaded from %systemroot% instead. Basically this makes exploitation still possible and even easier and more reliable.

How to change %systemroot%?
Simple: Through Volatile Environment.
Define your own %systemroot% in HKEY_CURRENT_USER\Volatile Environment and Sysprep will load precisely the DLL's specified in the manifest from there.

Very basic idea. In PoC, I figured out that for Windows 8/8.1 and for Windows 10 there are different DLL's. For Windows 10 it's "dbgcore.dll" and on Windows 8, "cryptbase.dll" works. The other DLL's have to be copied to the new %systemroot%, too, as they are loaded from there. For this, we just copy them from their original location.

Then, as we execute sysprep.exe, it will load all DLL's. The original ones that are just copies and our payload DLL as well.
In our payload DLL, we then restore the environment variable and run our code in high IL. In this example, Payload.exe will be started, which is an exemplary payload file displaying a MessageBox.

Why more reliable? Because no explorer.exe injection with IFileOperation is required anymore. This means only one DLL and less to worry about potential race conditions.

## Expected Result

When everything worked correctly, Payload.exe should be executed, displaying basic information including integrity level.

![](https://bytecode77.com/images/pages/sysprep-privilege-escalation/result.png)

## Downloads

Compiled binaries with example payload:

[![](http://bytecode77.com/public/fileicons/zip.png) SysprepVolatileEnvironmentLPE.zip](https://bytecode77.com/downloads/SysprepVolatileEnvironmentLPE.zip)

## Project Page

[![](https://bytecode77.com/public/favicon16.png) bytecode77.com/sysprep-privilege-escalation](https://bytecode77.com/sysprep-privilege-escalation)