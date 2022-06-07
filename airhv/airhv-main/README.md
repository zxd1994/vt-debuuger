# airhv

airhv is a simple hypervisor based on Intel VT-x mainly focused on ept hooking
## Features
* Ept support with mapping of 2MB pages (splitted dynamicly to 4KB pages if needed)
* Ability to run in VMWare which is using few IO ports for communication between vmtools and VMWare hypervisor
* Ability to handle various VM-exit cases: `CPUID` `RDTSC` `RDTSCP` `RDRAND` `RDSEED` `WBINVD/INVD` `IN/OUT` `XSETBV` `RDMSR` `WRMSR` `INVPCID` `MOV DR` `CR ACCESS` `EXCEPTIONS/NMI` `VMCALL` `INVLPG`  `GDTR/IDTR ACCESS` `LDTR/TR ACCESS`
* Ability to perform inline hooking via ept
* Included simple driver (airhvctrl) which is communicating with hypervisor via `VMCALL` to hook syscall (via ept).
It hooks NtCreateFile and every time user when tries to create a file named test.txt it prevents user from doing that.

## Future possible features
* Ability to run under AMD-SVM
* Ability to handle more VM-exit cases
* Ability to make hypervisor not detectable via counters (rdtsc,rdtscp)
* Ability to run nested VMs
* MSR_LSTAR hooking

## Compilation

Compile with Visual Studio 2019 (Requires [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk))

## Supported hardware
Intel processors with VT-x and EPT support

## Supported platforms
Windows 7 - Windows 10, x64 only

## License
airhv is under MIT license.  
Dependencies are licensed by their own licenses.
