# PErser (PE Parser)

## Introduction
PErser (as in PE Parser) is a small program made as an exercise to read the PE format and print out relevant information contained in its header.

Some of the files that use PE headers includes:
.acm, .ax, .cpl, .dll, .drv, .efi, .exe, .mui, .ocx, .scr, .sys, .tsp


## Building / Compiling
```
$ git clone https://github.com/adabz/PErser
$ cd PErser/
$ make
```

## Usage Example
```
$ ./perser ../samples-pe/explorer.exe

=== PE header information ===
Signature:        0x4550 (PE)
Machine:          (8664)  IMAGE_FILE_MACHINE_AMD64
number of sections:      8
TimeDateStamp:           0x57899981
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
SizeOfCode:              0x1a8000
SizeOfInitializedData:   0x2c4a00
SizeOfUninitializedData: 0x200
EntryPoint:       0x9eb60
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
SizeOfImage:            0x472000
SizeOfHeaders:   0x400
CheckSum:        0x482a3b
Subsystem:    (2)   IMAGE_SUBSYSTEM_WINDOWS_GUI
DllCharacteristics:        
     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
     IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     IMAGE_DLLCHARACTERISTICS_GUARD_CF
     IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
SizeOfStackReserve:     0x80000
SizeOfStackCommit:      0xe000
SizeOfHeapReserve:      0x100000
SizeOfHeapCommit:       0x1000
LoaderFlags:            0x0
NumberOfRvaAndSizes:    0x10

```


## To-do list / Progress
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint
- [x] Replce use of fgetc() functions for reading integers with  get16_le(), get32_le()...etc
- [x] Read OptionalHeader (standard) and windows-specific
- [x] Create separate structure for OptionalHeader
- [ ] Read and print PE sections (name, size, permissions)
- [ ] Implement functions to output parse-able text (for example, csv)
- [ ] Read basic DataDirectory info
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

