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
Characteristics:       EXE 
Optional Image header: 0x10b PE (32 bit) 
Address of EntryPoint: 0x285440 (0x10285440) 
Image Base:            0x10000000 

```

## To-do list / Progress
- [x] Find and read PE info
- [x] Determine PE file type (PE / PE+)
- [x] Find and Print address of EntryPoint 
- [ ] Read and print PE sections
- [ ] Replce fgetc() functions with appropriate functions
- [ ] Create Separate functions to read PE info
- [ ] Improve the code's read-ability

