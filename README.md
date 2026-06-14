[![CICD](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml/badge.svg?branch=main)](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml)
![AssemblyScript](https://img.shields.io/badge/assembly%20script-%23000000.svg?style=for-the-badge&logo=assemblyscript&logoColor=white)
![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/petergabaldon)

# WhatAboutSAM

WhatAboutSAM is my custom Windows SAM dumper. It can read SAM material directly from the live registry or from offline hives exposed through a Shadow Snapshot. The live registry method needs SYSTEM privileges, while the Shadow Snapshot method only needs an elevated administrator context because it reads the SAM and SYSTEM hives from a VSS snapshot. I wanted to study at a low level how Windows stores local user credentials in the Security Account Manager (SAM). As a Cybersecurity Engineer with a mostly offensive mindset, I have used many times the tools we all know: mimikatz, secretsdump (impacket), pwdump, hashdump (metasploit), crackmapexec (--sam parameter), LaZAgne...

Also, I wanted to practice some malware development techniques (enumerated below) and I needed an excuse for it. That is why I decided to implement my custom *SAM Dumper*.

**It is currently in development.**

Please, take a look at the credits because without these projects this would not have been possible.

![Sample execution](/img/sample.exec.png)

## Characteristics and possibilities

- Live registry method (`-r`, `--registry`): reads the protected SAM and SYSTEM registry material through native `ntdll` calls. This method needs SYSTEM privileges.
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
- I believe I do not fortget any, if I am not right I will add it later :P
