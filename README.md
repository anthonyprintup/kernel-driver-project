# kernel-driver-project
A kernel driver that was used as a communications framework for memory introspection of user-mode processes.

### Features:
- Simple debugger detection (anti-debug) mechanisms ([Main.cpp](Main.cpp));
- Berkeley sockets implementation using [Winsock Kernel](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-winsock-kernel) (WSK) for general purpose network IO ([Winsock Kernel](Miscellaneous/Net%20IO/Winsock%20Kernel));
- HTTP and TLS 1.2 client implementations for communicating with Microsoft servers when downloading and parsing PDBs ([HTTP](Miscellaneous/Net%20IO/HTTP), [TLS](Miscellaneous/Net%20IO/TLS));
- Symbol resolution and PDB type parsing ([Globals.cpp](Miscellaneous/Globals.cpp), [Symbols.cpp](Miscellaneous/Symbols.cpp), [Pdb](Miscellaneous/Pdb));
- Encrypted caches on disk to avoid unnecessary network IO ([Symbols.cpp#76](Miscellaneous/Symbols.cpp#L76));
- Unique hardware identification methods using data provided by the platform's hardware components (SMBIOS and EFI) and their respective parsers ([Hardware Id.cpp](Miscellaneous/Security/Hardware%20Id.cpp), [efi.cpp](Miscellaneous/Security/efi.cpp), [smbios.cpp](Miscellaneous/Security/smbios.cpp));
- Disk serial spoofer (storage query property, S.M.A.R.T.) using device object hooks ([Disk.cpp](Spoofer/Disk.cpp));
- Various utilities for interacting with and manipulating the Windows kernel-mode environment ([Kernel Mode.cpp](Utilities/NT/Kernel%20Mode.cpp), [Driver.cpp](Utilities/NT/Driver.cpp), [Ntoskrnl.cpp](Utilities/NT/Ntoskrnl.cpp));
- Various utilities for safely interacting with user-mode processes ([User Mode.cpp](Utilities/NT/User%20Mode.cpp));
- System call hooks used for communication between the user-mode and kernel-mode components ([Hook.cpp](System%20Calls/Hook.cpp));
- A POC for communicating with the TOR protocol ([Main.cpp](Main.cpp));
- Virtualized routines to prevent static and dynamic binary inspection while keeping reasonable execution times.
