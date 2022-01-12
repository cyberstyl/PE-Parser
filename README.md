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
Signature:             PE
Machine:               Intel 386 
Number of Sections:    7
OptionalHeader size:   224 (0xe0)
Characteristics:       DLL 
Optional Image header: 0x10b PE (32 bit) 
Address of EntryPoint: 0x285440 (0x10285440) 
Image Base:            0x10000000 

```

## Progress and Future goals
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint 
- [ ] Improve the code's read-ability

