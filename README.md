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
$ ./perser ../samples-pe/Chakra.dll 
showing file: ../samples-pe/Chakra.dll 

DOS Magic bytes: MZ
PE Offset:       f0

=== PE header information ===
Signature:        0x4550 (PE) 
Machine:          (14c)  IMAGE_FILE_MACHINE_I386
number of sections:      7
TimeDateStamp:           0x90aa65d2
PointerToSymbolTable:    0x0
NumberOfSymbols:         0
Size of OpionalHeader:   0xe0
Characteristics:         0x2102
     IMAGE_FILE_DLL 
     IMAGE_FILE_EXECUTABLE_IMAGE 
     IMAGE_FILE_32BIT_MACHINE

=== Optional header standard fields ===
Magic:      10b (PE) 
MajorLinkerVersion:      0xe
MinorLinkerVersion:      0x14
SizeOfCode:              0x546000
SizeOfInitializedData:   0x150e00
SizeOfUninitializedData: 0x0
EntryPoint:       0x285440
BaseOfCode:       0x1000

=== Optional header windows-specific fields ===
BaseOfData:           0x547000
ImageBase:              0x10000000
SectionAlignment:       0x1000
FileAlignment:          0x200
MajorOperatingSystemVersion:      0xa
MinorOperatingSystemVersion:      0x0
MajorImageVersion:      0xa
MinorImageVersion:      0x0
MajorSubsystemVersion:  0xa
MinorSubsystemVersion:  0x0
Win32VersionValue:      0x0
SizeOfImage:            0x69c000
SizeOfHeaders:   0x400
CheckSum:        0x5921cf
Subsystem:    (3)   IMAGE_SUBSYSTEM_WINDOWS_CUI
DllCharacteristics:        
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     IMAGE_DLLCHARACTERISTICS_GUARD_CF
SizeOfStackReserve:     0x40000
SizeOfStackCommit:      0x1000
SizeOfHeapReserve:      0x100000
SizeOfHeapCommit:       0x1000
LoaderFlags:            0x0
NumberOfRvaAndSizes:    0x10

========================
Data Tables 
Export Table:
      Virtual Address: 545ba0 (offset: 544fa0)
      Size:            145e
Import Table:
      Virtual Address: 65f6c8 (offset: 5558c8)
      Size:            3d4
Resource Table:
      Virtual Address: 665000 (offset: 558c00)
      Size:            3e8
Base Relocation Table:
      Virtual Address: 666000 (offset: 559000)
      Size:            35ab4
Debug:
      Virtual Address: b16f0 (offset: b0af0)
      Size:            54
TLS Table:
      Virtual Address: 18cb0 (offset: 180b0)
      Size:            18
Load Config Table:
      Virtual Address: 17d50 (offset: 17150)
      Size:            ac
IAT:
      Virtual Address: 65f000 (offset: 555200)
      Size:            6c4
Delay Import Descriptor:
      Virtual Address: 545864 (offset: 544c64)
      Size:            c0

========================
Sections: 
   Name: .text
       VirtualAddress: 1000
       VirtualSize:    545ffe
       SizeOfRawData:  546000
       PointerToRawData:   400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   60000020
          IMAGE_SCN_CNT_CODE
          IMAGE_SCN_MEM_EXECUTE
          IMAGE_SCN_MEM_READ
   Name: .data
       VirtualAddress: 547000
       VirtualSize:    117338
       SizeOfRawData:  ee00
       PointerToRawData:   546400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .idata
       VirtualAddress: 65f000
       VirtualSize:    3422
       SizeOfRawData:  3600
       PointerToRawData:   555200
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .didat
       VirtualAddress: 663000
       VirtualSize:    a8
       SizeOfRawData:  200
       PointerToRawData:   558800
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .mrdata
       VirtualAddress: 664000
       VirtualSize:    1
       SizeOfRawData:  200
       PointerToRawData:   558a00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .rsrc
       VirtualAddress: 665000
       VirtualSize:    3e8
       SizeOfRawData:  400
       PointerToRawData:   558c00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .reloc
       VirtualAddress: 666000
       VirtualSize:    35ab4
       SizeOfRawData:  35c00
       PointerToRawData:   559000
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   42000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_DISCARDABLE
          IMAGE_SCN_MEM_READ

```

## To-do list / Progress
- [x] Find and read PE info.
- [x] Determine PE file type (PE / PE+).
- [x] Find and Print address of EntryPoint.
- [x] Replce use of fgetc() functions for reading integers with  get16_le(), get32_le()...etc.
- [x] Read OptionalHeader (standard) and windows-specific.
- [x] Create separate structure for OptionalHeader.
- [x] Added build files for Microsoft Visual Studio (tested on Visual Studio 2015).
- [ ] Add separate functions to handle memory allocation/cleanup.
    - [x] Added separate function that cleans up allocated memory.
- [x] Add code to read DOS header.
- [x] Read and print PE sections (name, size, permissions).
- [ ] Implement functions to output parse-able text (for example, csv).
- [x] Read basic DataDirectory info.
- [ ] Read imported functions (by name).
- [ ] Read imported functions (by ordinal).
- [x] Read Export DataDirectory section.
- [x] Create Separate functions to read PE info.
- [x] Add ability to read all PE files in a current or given directory.
- [ ] Add ability to search for and handle PE files recursively.
- [ ] Improve the code's read-ability.
    - [ ] Break the content of pe_interface.c into two files.
    - [ ] Enforce consistent naming convention for struct members (for example objectName1).
    - [ ] Enforce having one function perform one task (whenever possible).
- [ ] Release a compiled binary beta.


## Resources
During the making of this program I've used:
- [aldeid wiki - PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable)
- [Microsoft PE format documentation](
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Ange Albertini's Visual PE101 documentation of the PE format](
https://github.com/corkami/pics/tree/master/binary/pe101)
