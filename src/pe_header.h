// pe_header.h
//    Definitions and declarations for PE module
#ifndef PE_HEADER_H
#define PE_HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// PE header
typedef struct pe_file
{
  int   PE_offset;               // PE offset
  char  *sig;                    // PE signature
  uint16_t   machine;            // Machine type ARM/MIPS/Intel
  uint16_t   numberOfSections;   // Number of Sections
  uint32_t   timeStamp;          // time date stamp
  uint32_t   SymTablPtr;         // Pointer to symbol table
  uint32_t   numberOfSym;        // number of symbols
  uint16_t   optionalHeaderSize; // Optional Header Size
  uint16_t   characteristics;    // Characteristics

  int   optionalImage;           // Optional Image Header
  int   EntryPoint;
  int64_t    ImageBase;
} pe_file;


// Optional Header Image
typedef struct OptionalHeader{
  uint16_t  magic;  
  uint8_t   majorLinkerVer;
  uint8_t   minorLinkerVer;
  uint32_t  sizeOfCode;
  uint32_t  sizeOfInitializedData;
  uint32_t  sizeOfUninitializedData;
  uint32_t  EntryPoint;
  uint32_t  baseOfCode;

} OptionalHeader;

// functions
void      print_info(pe_file *file);
void      read_pe(char *filename, pe_file *file);
void      read_OpionalHeader(FILE *in);
void      print_characteristics(uint16_t ch);
char     *get_Sig(FILE *in);
uint32_t   get_elfnew(FILE *in);
uint16_t  get16_le(FILE *in);
uint32_t  get32_le(FILE *in);
uint64_t  get64_le(FILE *in);

// Machine types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
#define IMAGE_FILE_MACHINE_UNKNOWN   	 0x0      //    The content of this field is assumed to be applicable to any machine type
#define IMAGE_FILE_MACHINE_IA64   		 0x200    //    Intel Itanium processor family
#define IMAGE_FILE_MACHINE_I386   		 0x14c    //    Intel 386 or later processors and compatible processors
#define IMAGE_FILE_MACHINE_AMD64   		 0x8664   //    x64
#define IMAGE_FILE_MACHINE_ARM   		   0x1c0    //    ARM little endian
#define IMAGE_FILE_MACHINE_ARM64   		 0xaa64   //    ARM64 little endian
#define IMAGE_FILE_MACHINE_ARMNT   		 0x1c4    //    ARM Thumb-2 little endian
#define IMAGE_FILE_MACHINE_EBC   		   0xebc    //    EFI byte code


// Characteristics
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
#define IMAGE_FILE_RELOCS_STRIPPED        		0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE       		0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED     		0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED    		0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM     		0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE    		0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO      		0x0080
#define IMAGE_FILE_32BIT_MACHINE          		0x0100
#define IMAGE_FILE_DEBUG_STRIPPED         		0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP     	  	0x0800
#define IMAGE_FILE_SYSTEM     			       		0x1000
#define IMAGE_FILE_DLL     					         	0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY       			0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI       		0x8000

// PE optional image
#define OPTIONAL_IMAGE_32 0x10b
#define OPTIONAL_IMAGE_64 0x20b
#endif