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

Magic bytes:            MZ
PE Offset               F0

PE header information
 Signature:             0x4550 (PE) 
 Machine:               (14C)  IMAGE_FILE_MACHINE_I386
 Sections:              7
 Time Stamp:            0x90AA65D2
 Symbol Table Pointer:  0x0
 Symbols:               0
 OpionalHeader Size:    224 (0xE0)
 Characteristics:       0x2102
     IMAGE_FILE_EXECUTABLE_IMAGE
     IMAGE_FILE_32BIT_MACHINE
     IMAGE_FILE_DLL

Optional Header
Magic:      10B (PE) 
MajorLinkerVersion:      0xE
MinorLinkerVersion:      0x14
SizeOfCode:              0x546000
SizeOfInitializedData:   0x150E00
SizeOfUninitializedData: 0x0
EntryPoint:              0x285440
BaseOfCode:              0x1000
BaseOfData:              0x547000
ImageBase:               0x10000000
SectionAlignment:        0x1000
FileAlignment:           0x200
MajorOSVersion:          0xA
MinorOSVersion:          0x0
MajorImageVersion:       0xA
MinorImageVersion:       0x0
MajorSubsysVersion:      0xA
MinorSubsysVersion:      0x0
Win32VersionValue:       0x0
SizeOfImage:             0x69C000
SizeOfHeaders:           0x400
CheckSum:                0x5921CF
Subsystem:               (3)   IMAGE_SUBSYSTEM_WINDOWS_CUI
DllCharacteristics:           
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     IMAGE_DLLCHARACTERISTICS_GUARD_CF
SizeOfStackReserve:      0x40000
SizeOfStackCommit:       0x1000
SizeOfHeapReserve:       0x100000
SizeOfHeapCommit:        0x1000
LoaderFlags:             0x0
NumberOfRvaAndSizes:     16

Data Tables: 
  Export Table: 
     Address: 0x545BA0  Offset: 544FA0
        Size: 0x145E 
  Import Table: 
     Address: 0x65F6C8  Offset: 5558C8
        Size: 0x3D4 
  Resource Table: 
     Address: 0x665000  Offset: 558C00
        Size: 0x3E8 
  Base Relocation: 
     Address: 0x666000  Offset: 559000
        Size: 0x35AB4 
  Debug Table: 
     Address: 0xB16F0   Offset: B0AF0
        Size: 0x54 
  TLS Table: 
     Address: 0x18CB0   Offset: 180B0
        Size: 0x18 
  Load Config : 
     Address: 0x17D50   Offset: 17150
        Size: 0xAC 
  Import Address: 
     Address: 0x65F000  Offset: 555200
        Size: 0x6C4 
  Delay Import Desc.: 
     Address: 0x545864  Offset: 544C64
        Size: 0xC0 

Sections: 
   Name: .text
       VirtualAddress:        1000
       VirtualSize:           545FFE
       SizeOfRawData:         546000
       PointerToRawData:      400
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       60000020
          IMAGE_SCN_CNT_CODE
          IMAGE_SCN_MEM_EXECUTE
          IMAGE_SCN_MEM_READ
   Name: .data
       VirtualAddress:        547000
       VirtualSize:           117338
       SizeOfRawData:         EE00
       PointerToRawData:      546400
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       C0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .idata
       VirtualAddress:        65F000
       VirtualSize:           3422
       SizeOfRawData:         3600
       PointerToRawData:      555200
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .didat
       VirtualAddress:        663000
       VirtualSize:           A8
       SizeOfRawData:         200
       PointerToRawData:      558800
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       C0000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
          IMAGE_SCN_MEM_WRITE
   Name: .mrdata
       VirtualAddress:        664000
       VirtualSize:           1
       SizeOfRawData:         200
       PointerToRawData:      558A00
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .rsrc
       VirtualAddress:        665000
       VirtualSize:           3E8
       SizeOfRawData:         400
       PointerToRawData:      558C00
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       40000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_READ
   Name: .reloc
       VirtualAddress:        666000
       VirtualSize:           35AB4
       SizeOfRawData:         35C00
       PointerToRawData:      559000
       PointerToRelactons:    0
       PointerToLinenumbers:  0
       NumberOfRelocations:   0
       NumberOfLinenumbers:   0
       Characteristics:       42000040
          IMAGE_SCN_CNT_INITIALIZED_DATA
          IMAGE_SCN_MEM_DISCARDABLE
          IMAGE_SCN_MEM_READ

Export Directory 
    Flags:           0x0
    TimeStamp:       0x90AA65D2
    MajorVersion:    0x0
    MinorVersion:    0x0
    Name RVA:        0x546208
    OrdinalBase:     0x190
    AddressTable Entries:  0xA0
    NumberOfNames:         0xA0
    ExportTable Entries:   0x545BC8
    AddressOfNames:        0x545E48
    OrdinalTable RVA:      0x5460C8

```

## Bugs / Improvments
- [x] fseek() fails under windows
  - issue was due to how the functions read32_le(), read64_le()...etc were designed, they compiled fine under gcc, but due to opposite order of operations under visual studio compiler, the functions read/wrote data backwards, causing invalid reads of PE header and breaking fseek().
- [x] Visual Studio refuses to compile for a char array of size 0
  - instead of the convulted way written in read_str() function to read a number of bytes as a string, I've updated the function to read one byte at a time and save into an allocated memory.


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
- [x] read_str() needs to be re-written.
- [x] print_clean() to be used in place of print_info() for cleaner output.
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
