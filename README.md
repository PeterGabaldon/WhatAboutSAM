[![CICD](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml/badge.svg?branch=main)](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml)
![AssemblyScript](https://img.shields.io/badge/assembly%20script-%23000000.svg?style=for-the-badge&logo=assemblyscript&logoColor=white)
![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/petergabaldon)

# WhatAboutSAM

## ⚠️ Disclaimer: Authorized Educational Use Only

This project is intended strictly for cybersecurity education and authorized security research. It may only be used in environments where you have clear, prior, and explicit permission to perform credential and SAM-related testing, such as systems you own or systems covered by a valid authorization agreement.

By no means may this project be used against any system, account, network, or data without prior authorization. Unauthorized use is prohibited and may violate applicable laws, policies, and professional ethics. Users are solely responsible for ensuring that every use of this project is lawful, permitted, and properly scoped.

## Introduction

WhatAboutSAM is my custom Windows SAM dumper. It can read SAM material directly from the live registry or from offline hives exposed through a Shadow Snapshot. The live registry method needs SYSTEM privileges, unless the DACL write modifier is used, while the Shadow Snapshot method only needs an elevated administrator context because it reads the SAM and SYSTEM hives from a VSS snapshot. I wanted to study at a low level how Windows stores local user credentials in the Security Account Manager (SAM). As a Cybersecurity Engineer with a mostly offensive mindset, I have used many times the tools we all know: mimikatz, secretsdump (impacket), pwdump, hashdump (metasploit), crackmapexec (--sam parameter), LaZAgne...

Also, I wanted to practice some malware development techniques (enumerated below) and I needed an excuse for it. That is why I decided to implement my custom *SAM Dumper*.

**It is currently in development.**

Please, take a look at the credits because without these projects this would not have been possible.

![Sample execution](/img/sample.exec.png)

## Characteristics and possibilities

- Live registry method (`-r`, `--registry`): reads the protected SAM and SYSTEM registry material through native `ntdll` calls. This method needs SYSTEM privileges.
- DACL write modifier (`-dacl`, `--dacl-write`): used together with the live registry method, it enables `SeTakeOwnershipPrivilege`, `SeRestorePrivilege` and `SeBackupPrivilege` through `RtlAdjustPrivilege`, then saves the original owner and DACL with `NtOpenKeyEx` + `NtQuerySecurityObject` (backup semantics), takes the ownership and rewrites the DACL with `NtSetSecurityObject` by copying the original DACL and appending the Administrators `KEY_READ`-with-inheritance ACE to it, so the current permissions remain active the whole time and a crash never leaves a key without its original ACEs — for exactly the keys the live dump opens, and no others: `\Registry\Machine\SAM\SAM\Domains\Account`, `\Registry\Machine\SAM\SAM\Domains\Account\Users` plus its `00xxxxxx` RID subkeys (the same first `MAX_SAM_ENTRIES` window the dump itself walks) and the four boot-key class keys `\Registry\Machine\SYSTEM\CurrentControlSet\Control\Lsa\JD`, `\Lsa\Skew1`, `\Lsa\GBG` and `\Lsa\Data`. Every key is treated individually because protected DACLs on child keys never inherit a grant from their parent. After the dump the original owner and DACL of every touched key are restored with `NtSetSecurityObject`. This way an elevated Administrator can run the live registry method without SYSTEM privileges.
- Shadow Snapshot method (`-ss`, `--shadowSnapshot`): creates a VSS snapshot of `C:\`, reads `Windows\System32\Config\SAM` and `Windows\System32\Config\SYSTEM` from the snapshot, and parses the offline hives with `Offreg.dll`. This method needs administrator privileges, not SYSTEM privileges.
- NTLM hash recovery: extracts local user records, derives the bootkey/syskey material, and prints NTLM hashes for local accounts.
- SAM format handling: supports the post-Windows 10 1909 AES-based path and includes the legacy RC4-based path, which still needs more testing.
- Native API resolution: walks the PEB and uses API hashing to resolve `ntdll` exports without calling `GetModuleHandle` or `GetProcAddress`.
- Optional call stack spoofing path (`-cc`, `--customCallback`): proxies selected native calls through custom callbacks.
- Debug output (`-d`, `--debug`): prints detailed acquisition and decryption traces for development and research.

## TODO List

- [x] PEB Walking (avoid GetModuleHandle + GetProcAddress)
- [x] Call Stack Spoofing with Custom Callbacks (Thread Pools)
- [x] Native Functions
- [x] API Hashing
- [x] Travis CI (Finally done with Github Actions)
- [x] Debug Branch vs Release Branch
- [x] Shadow Snapshot Method
- [ ] Test Old Algorithm. What a bummer. Microsoft Changed storage in SAM in Windows 10 1909
- [x] Command Line Parameters
- [ ] Add more comments :)
- [x] Debug prints
- [ ] Add optional SYSTEM elevation for the live registry method


## Credits

Please, take a look to these projects, without them I could not have developed WhatAboutSAM.

- https://github.com/Maldev-Academy/MaldevAcademyLdr.1/tree/main/HashCalculator
- https://github.com/tobiohlala/NTLMX
- https://0xdarkvortex.dev/proxying-dll-loads-for-hiding-etwti-stack-tracing/
- https://0xdarkvortex.dev/hiding-in-plainsight/
- https://0xpat.github.io/Malware_development_part_4/
- https://github.com/gentilkiwi/mimikatz
- https://www.ired.team/miscellaneous-reversing-forensics/aes-encryption-example-using-cryptopp-.lib-in-visual-studio-c++
- https://cryptopp.com/docs/ref/
- https://github.com/ShiftMediaProject/VSNASM
- https://github.com/PeterGabaldon/WhatAboutSAM/issues/10 (DACL write trick, reported by @Lectureinmud)
- I believe I do not fortget any, if I am not right I will add it later :P
