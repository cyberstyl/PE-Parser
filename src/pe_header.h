// pe_header.h
//    Definitions and declarations for PE module
#ifndef PE_HEADER_H
#define PE_HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


typedef struct pe_file
{
  int   PE_offset;      // PE offset
  char  *sig;         // PE signature
  int   machine;        // Machine type ARM/MIPS/Intel
  int   sections;       // Number of Sections
  int   characteristics;          // Characteristics
  int   optionalHeaderSize;        // Optional Header Size
  int   optionalImage;             // Optional Image Header
  int   EntryPoint;
  int64_t    ImageBase;
} pe_file;

// functions
void      print_info(pe_file *file);
void      read_pe(char *filename, pe_file *file);
void      read_OpionalHeader(FILE *in);
char     *get_Sig(FILE *in);
uint8_t   get_elfnew(FILE *in);
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
#define IMAGE_FILE_LARGE_ADDRESS_ AWARE   		0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO      		0x0080
#define IMAGE_FILE_32BIT_MACHINE          		0x0100
#define IMAGE_FILE_DEBUG_STRIPPED         		0x0200
#define IMAGE_FILE_SYSTEM     		      			0x1000
#define IMAGE_FILE_DLL     				        		0x2000
#define IMAGE_FILE_BYTES_REVERSED_HI      		0x8000

// PE optional image
#define OPTIONAL_IMAGE_32 0x10b
#define OPTIONAL_IMAGE_64 0x20b
#endif