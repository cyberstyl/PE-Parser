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
Machine:               x64 
Number of Sections:     6
OptionalHeader size:    0xf0
Characteristics:        0xc22
Optional Image header:  0x20b PE+ (64 bit)

```

## Progress and Future goals
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint 
- [ ] Improve the code's read-ability

