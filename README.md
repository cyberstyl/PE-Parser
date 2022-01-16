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
$ ./perser ../samples-pe/setup.exe 
showing file: ../samples-pe/setup.exe 

==============
magic: MZ
el_fanew: e8

=== PE header information ===
Signature:        0x4550 (PE) 
Machine:          (8664)  IMAGE_FILE_MACHINE_AMD64
number of sections:      6
TimeDateStamp:           0x8213988a
PointerToSymbolTable:    0x0
NumberOfSymbols:         0
Size of OpionalHeader:   0xf0
Characteristics:         0xc22
     IMAGE_FILE_EXECUTABLE_IMAGE 
     IMAGE_FILE_LARGE_ADDRESS_AWARE
     IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
     IMAGE_FILE_NET_RUN_FROM_SWAP

=== Optional header standard fields ===
Magic:      20b (PE+) 
MajorLinkerVersion:      0xe
MinorLinkerVersion:      0x14
SizeOfCode:              0x1a00
SizeOfInitializedData:   0xe800
SizeOfUninitializedData: 0x0
EntryPoint:       0x22c0
BaseOfCode:       0x1000

=== Optional header windows-specific fields ===
ImageBase:              0x140000000
SectionAlignment:       0x1000
FileAlignment:          0x200
MajorOperatingSystemVersion:      0xa
MinorOperatingSystemVersion:      0x0
MajorImageVersion:      0xa
MinorImageVersion:      0x0
MajorSubsystemVersion:  0x6
MinorSubsystemVersion:  0x0
Win32VersionValue:      0x0
SizeOfImage:            0x15000
SizeOfHeaders:   0x400
CheckSum:        0x19245
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
      Virtual Address: 398c
      Size:            64
Resource Table:
      Virtual Address: 7000
      Size:            c840
Exception Table:
      Virtual Address: 6000
      Size:            1b0
Certificate Table:
      Virtual Address: 10000
      Size:            21c8
Base Relocation Table:
      Virtual Address: 14000
      Size:            20
Debug:
      Virtual Address: 3520
      Size:            54
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
      Virtual Address: 3020
      Size:            118
Bound Import:
      Virtual Address: 0
      Size:            0
IAT:
      Virtual Address: 3138
      Size:            220
Delay Import Descriptor:
      Virtual Address: 0
      Size:            0
CLR Runtime Header:
      Virtual Address: 0
      Size:            0

========================
Sections: 
   Name: .text
       VirtualAddress: 1000
       VirtualSize:    1930
       SizeOfRawData:  1a00
       PointerToRawData:   400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   60000020
          IMAGE_SCN_CNT_CODE
          IMAGE_SCN_MEM_EXECUTE
          IMAGE_SCN_MEM_READ
   Name: .rdata
       VirtualAddress: 3000
       VirtualSize:    10a0
       SizeOfRawData:  1200
       PointerToRawData:   1e00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .data
       VirtualAddress: 5000
       VirtualSize:    680
       SizeOfRawData:  200
       PointerToRawData:   3000
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .pdata
       VirtualAddress: 6000
       VirtualSize:    1b0
       SizeOfRawData:  200
       PointerToRawData:   3200
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .rsrc
       VirtualAddress: 7000
       VirtualSize:    c840
       SizeOfRawData:  ca00
       PointerToRawData:   3400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .reloc
       VirtualAddress: 14000
       VirtualSize:    20
       SizeOfRawData:  200
       PointerToRawData:   fe00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   42000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_DISCARDABLE
          IMAGE_SCN_MEM_READ

==================

```

## To-do list / Progress
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint
- [x] Replce use of fgetc() functions for reading integers with  get16_le(), get32_le()...etc
- [x] Read OptionalHeader (standard) and windows-specific
- [x] Create separate structure for OptionalHeader
- [x] Added build files for Microsoft Visual Studio (tested on Visual Studio 2015)
- [ ] Add separate functions to handle memory allocation/cleanup.
- [x] Add code to read DOS header
- [x] Read and print PE sections (name, size, permissions)
- [ ] Implement functions to output parse-able text (for example, csv)
- [x] Read basic DataDirectory info
- [ ] Read imported functions (by name)
- [ ] Read imported functions (by ordinal)
- [x] Read Export DataDirectory section
- [ ] Create Separate functions to read PE info
- [x] Add ability to read all PE files in a current or given directory
- [ ] Add ability to search for and handle PE files recursively
- [ ] Improve the code's read-ability
    - [ ] Break the content of pe_interface.c into two files
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
