[![CICD](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml/badge.svg?branch=main)](https://github.com/PeterGabaldon/WhatAboutSAM/actions/workflows/cicd.yml)
![AssemblyScript](https://img.shields.io/badge/assembly%20script-%23000000.svg?style=for-the-badge&logo=assemblyscript&logoColor=white)
![C](https://img.shields.io/badge/c-%2300599C.svg?style=for-the-badge&logo=c&logoColor=white)
![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
[Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)

# WhatAboutSAM

WhatAboutSAM is my custom Windows SAM dumper, reading it from the registry. So, SYSTEM privileges are needed. I wanted to study at a low level how Windows stores local user credentials in the Security Account Manager (SAM). As a Cybersecurity Engineer with a mostly offensive mindset, I have used many times the tools we all know: mimikatz, secretsdump (impacket), pwdump, hashdump (metasploit), crackmapexec (--sam parameter), LaZAgne...

Also, I wanted to practice some malware development techniques (enumerated below) and I needed an excuse for it. That is why I decided to implement my custom *SAM Dumper*.

**It is currently in development.**

Please, take a look at the credits because without these projects this would not have been possible.

![Sample execution](/img/sample.exec.png)

## TODO List

- [x] PEB Walking (avoid GetModuleHandle + GetProcAddress)
- [x] Call Stack Spoofing with Custom Callbacks (Thread Pools)
- [x] Native Functions
- [x] API Hashing
- [x] Travis CI (Finally done with Github Actions)
- [x] Debug Branch vs Release Branch
- [ ] Shadow Snapshot Method
- [ ] Test Old Algorithm. What a bummer. Microsoft Changed storage in SAM in Windows 10 1909
- [ ] Command Line Parameters
- [ ] Elevate to SYSTEM


## Credits

Please, take a look to this project, without them I could not have developed WhatAboutSAM.

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


