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
showing file: ../samples-pe/explorer.exe 

Magic bytes:            MZ
PE Offset               E8

PE header information
 Signature:             0x4550 (PE) 
 Machine:               (8664)  IMAGE_FILE_MACHINE_AMD64
 Sections:              8
 Time Stamp:            0x57899981
 Symbol Table Pointer:  0x0
 Symbols:               0
 OpionalHeader Size:    240 (0xF0)
 Characteristics:       0x22
     IMAGE_FILE_EXECUTABLE_IMAGE
     IMAGE_FILE_LARGE_ADDRESS_AWARE

Optional Header
Magic:      20B (PE+) 
MajorLinkerVersion:      0xE
MinorLinkerVersion:      0x0
SizeOfCode:              0x1A8000
SizeOfInitializedData:   0x2C4A00
SizeOfUninitializedData: 0x200
EntryPoint:              0x9EB60
BaseOfCode:              0x1000
ImageBase:               0x140000000
SectionAlignment:        0x1000
FileAlignment:           0x200
MajorOSVersion:          0xA
MinorOSVersion:          0x0
MajorImageVersion:       0xA
MinorImageVersion:       0x0
MajorSubsysVersion:      0xA
MinorSubsysVersion:      0x0
Win32VersionValue:       0x0
SizeOfImage:             0x472000
SizeOfHeaders:           0x400
CheckSum:                0x482A3B
Subsystem:               (2)   IMAGE_SUBSYSTEM_WINDOWS_GUI
DllCharacteristics:           
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     IMAGE_DLLCHARACTERISTICS_GUARD_CF
     IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
SizeOfStackReserve:      0x80000
SizeOfStackCommit:       0xe000
SizeOfHeapReserve:       0x100000
SizeOfHeapCommit:        0x1000
LoaderFlags:             0x0
NumberOfRvaAndSizes:     16

Data Tables: 
  Import Table: 
     Address: 0x21B4B8   Offset: 2198B8
        Size: 0x5DC 
  Resource Table: 
     Address: 0x23F000   Offset: 236C00
        Size: 0x22E0D8 
  Exception Table: 
     Address: 0x228000   Offset: 221400
        Size: 0x1524C 
  Certificate : 
     Address: 0x468E00   Offset: 460A00
        Size: 0xC118 
  Base Relocation: 
     Address: 0x46E000   Offset: 464E00
        Size: 0x3F0C 
  Debug Table: 
     Address: 0x1E2B10   Offset: 1E0F10
        Size: 0x38 
  Load Config : 
     Address: 0x1B9AE0   Offset: 1B7EE0
        Size: 0xD0 
  Import Address: 
     Address: 0x1C8FB0   Offset: 1C73B0
        Size: 0x2040 
  Delay Import Desc.: 
     Address: 0x21A258   Offset: 218658
        Size: 0x440 

Sections: 
   Name: .text
       VirtualAddress: 1000
       VirtualSize:    1a7ed7
       SizeOfRawData:  1a8000
       PointerToRawData:   400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   60000020
          IMAGE_SCN_CNT_CODE
          IMAGE_SCN_MEM_EXECUTE
          IMAGE_SCN_MEM_READ
   Name: .imrsiv
       VirtualAddress: 1a9000
       VirtualSize:    4
       SizeOfRawData:  0
       PointerToRawData:   0
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000080
          IMAGE_SCN_CNT_UNINITIALIZED_ DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .rdata
       VirtualAddress: 1aa000
       VirtualSize:    780e4
       SizeOfRawData:  78200
       PointerToRawData:   1a8400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .data
       VirtualAddress: 223000
       VirtualSize:    4dbc
       SizeOfRawData:  e00
       PointerToRawData:   220600
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .pdata
       VirtualAddress: 228000
       VirtualSize:    1524c
       SizeOfRawData:  15400
       PointerToRawData:   221400
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .didat
       VirtualAddress: 23e000
       VirtualSize:    3a0
       SizeOfRawData:  400
       PointerToRawData:   236800
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   c0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .rsrc
       VirtualAddress: 23f000
       VirtualSize:    22e0d8
       SizeOfRawData:  22e200
       PointerToRawData:   236c00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .reloc
       VirtualAddress: 46e000
       VirtualSize:    3f0c
       SizeOfRawData:  4000
       PointerToRawData:   464e00
       PointerToRelactons: 0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:   42000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_DISCARDABLE
          IMAGE_SCN_MEM_READ

```

## Bugs / Improvments
- [ ] fseek() fails under windows
- [ ] Visual Studio refuses to compile for a char array of size 0


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
- [ ] read_str() needs to be re-written.
- [ ] print_clean() to be used in place of print_info() for cleaner output.
- [ ] Create Getter() functions to get values from struct (get_ImageBase(), get_Sections()...) instead of reading directly from struct.
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
