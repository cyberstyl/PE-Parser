# PErser (PE Parser)

## Introduction
PErser (as in PE Parser) is a small program made as an exercise to read the PE format and print out relevant information contained in its header.

Some of the files that use PE headers includes:
.acm, .ax, .cpl, .dll, .drv, .efi, .exe, .mui, .ocx, .scr, .sys, .tsp


## Building / Compiling / Running
The source code can be compiled and run on both Linux/Windows, using either gcc or Visual Studio (tested on Visual Studio 2015).

on Windows you can open the solution (PErser.sln) file and Build a solution of the project.
On Linux you can build and run the program in following steps.

```
$ git clone https://github.com/adabz/PErser
$ cd PErser/
$ make
$ ./perser ../samples-pe/explorer.exe

File: ../samples-pe/pwcreator.exe

=== PE header information ===
Signature:        0x4550 (PE) 
Machine:          (8664)  IMAGE_FILE_MACHINE_AMD64
number of sections:      6
TimeDateStamp:           0x57899a17
PointerToSymbolTable:    0x0
NumberOfSymbols:         0
Size of OpionalHeader:   0xf0
Characteristics:         0x22
     IMAGE_FILE_EXECUTABLE_IMAGE 
     IMAGE_FILE_LARGE_ADDRESS_AWARE

=== Optional header standard fields ===
Magic:      20b (PE+) 
MajorLinkerVersion:      0xe
MinorLinkerVersion:      0x0
SizeOfCode:              0x59c00
SizeOfInitializedData:   0x69e00
SizeOfUninitializedData: 0x0
EntryPoint:       0x52660
BaseOfCode:       0x1000

=== Optional header windows-specific fields ===
ImageBase:              0x140000000
SectionAlignment:       0x1000
FileAlignment:          0x200
MajorOperatingSystemVersion:      0xa
MinorOperatingSystemVersion:      0x0
MajorImageVersion:      0xa
MinorImageVersion:      0x0
MajorSubsystemVersion:  0xa
MinorSubsystemVersion:  0x0
Win32VersionValue:      0x0
SizeOfImage:            0xc7000
SizeOfHeaders:   0x400
CheckSum:        0xc5fb5
Subsystem:    (2)   IMAGE_SUBSYSTEM_WINDOWS_GUI
DllCharacteristics:        
     IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA  
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     IMAGE_DLLCHARACTERISTICS_GUARD_CF
     IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
SizeOfStackReserve:     0x80000
SizeOfStackCommit:      0x2000
SizeOfHeapReserve:      0x100000
SizeOfHeapCommit:       0x1000
LoaderFlags:            0x0
NumberOfRvaAndSizes:    0x10

========================
Data Tables 
Export Table:
      Virtual Address: 0
      Size:            0
Import Table:
      Virtual Address: 83020
      Size:            17c
Resource Table:
      Virtual Address: 8f000
      Size:            36190
Exception Table:
      Virtual Address: 8a000
      Size:            4494
Certificate Table:
      Virtual Address: 0
      Size:            0
Base Relocation Table:
      Virtual Address: c6000
      Size:            f18
Debug:
      Virtual Address: 70af0
      Size:            38
Architecture:
      Virtual Address: 0
      Size:            0
Global Ptr:
      Virtual Address: 0
      Size:            0
TLS Table:
      Virtual Address: 0
      Size:            0
Load Config Table:
      Virtual Address: 5f020
      Size:            d0
Bound Import:
      Virtual Address: 0
      Size:            0
IAT:
      Virtual Address: 5f0f0
      Size:            bf8
Delay Import Descriptor:
      Virtual Address: 0
      Size:            0
CLR Runtime Header:
      Virtual Address: 0
      Size:            0
Reserved, must be zero:
      Virtual Address: 0
      Size:            0

========================
Sections: 
   Name: .text
       VirtualAddress: 1000
       VirtualSize:    59a5a
       SizeOfRawData:  59c00
   Name: .rdata
       VirtualAddress: 5b000
       VirtualSize:    2a91c
       SizeOfRawData:  2aa00
   Name: .data
       VirtualAddress: 86000
       VirtualSize:    3a68
       SizeOfRawData:  2e00
   Name: .pdata
       VirtualAddress: 8a000
       VirtualSize:    4494
       SizeOfRawData:  4600
   Name: .rsrc
       VirtualAddress: 8f000
       VirtualSize:    36190
       SizeOfRawData:  36200
   Name: .reloc
       VirtualAddress: c6000
       VirtualSize:    f18
       SizeOfRawData:  1000
```


## To-do list / Progress
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint
- [x] Replce use of fgetc() functions for reading integers with  get16_le(), get32_le()...etc
- [x] Read OptionalHeader (standard) and windows-specific
- [x] Create separate structure for OptionalHeader
- [x] Added build files for Microsoft Visual Studio (tested on Visual Studio 2015)
- [ ] Add code to read DOS header
- [ ] Read and print PE sections (name, size, permissions)
- [ ] Implement functions to output parse-able text (for example, csv)
- [x] Read basic DataDirectory info
- [ ] Read imported functions (by name)
- [ ] Read imported functions (by ordinal)
- [ ] Create Separate functions to read PE info
- [x] Add ability to read all PE files in a current or given directory
- [ ] Add ability to search for and handle PE files recursively
- [ ] Improve the code's read-ability
    - [ ] Enforce consistent naming convention for struct members (for example objectName1)
    - [ ] Enforce having one function perform one task (whenever possible)
- [ ] Release a compiled binary beta


## Resources
During the making of this program I've used:
- [aldeid wiki - PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable)
- [Microsoft PE format documentation](
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Ange Albertini's Visual PE101 documentation of the PE format](
https://github.com/corkami/pics/tree/master/binary/pe101)

