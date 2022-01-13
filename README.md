# PErser (PE Parser)

## Introduction
PErser (as in PE Parser) is a small program made as an exercise to read header information from Portable Executable files.

## Building / Compiling
```
$ cd PErser/
$ make
```

## Usage Example
```
$ ./perser example-file.exe
=== PE header information ===
Signature:          0x4550 (PE)
Machine:            IMAGE_FILE_MACHINE_AMD64
number of sections:    8
Size of OpionalHeader: 0xf0
Characteristics:
     IMAGE_FILE_EXECUTABLE_IMAGE
     IMAGE_FILE_LARGE_ADDRESS_AWARE
Magic:      0x20b (PE+)
MajorLinkerVersion:  0xe
MinorLinkerVersion:  0x14
SizeOfCode:       0xe
SizeOfInitializedData: 0x217000
SizeOfUninitializedData: 0x200
SizeOfCode:       0xe

```

## Resources
During the making of this program I've used:
- [aldeid wiki - PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable)
- [Microsoft PE format documentation](
https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Ange Albertini's Visual PE101 documentation of the PE format](
https://github.com/corkami/pics/tree/master/binary/pe101)


## To-do list / Progress
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint
- [x] Replce use of fgetc() functions for reading integers with  get16_le(), get32_le()...etc
- [ ] Read OptionalHeader (standard) and windows-specific
- [ ] Create separate structure for OptionalHeader
- [ ] Read and print PE sections (name, size, permissions)
- [ ] Implement functions to ouput parse-able text (for example, csv)
- [ ] Read basic DataDirectory info
- [ ] Read imported functions (by name)
- [ ] Read imported functions (by ordinal)
- [ ] Create Separate functions to read PE info
- [ ] Add ability to read all PE files in a current or given directory
- [ ] Add ability to search for and handle PE files recursively
- [ ] Improve the code's read-ability
    - [ ] Enforce consistent naming convention for struct members (for example objectName1)
    - [ ] TBD
- [ ] Release a compiled binary beta
