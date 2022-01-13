// pe_header.h
//    Definitions and declarations for PE module
//
#ifndef PE_HEADER_H
#define PE_HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


// Optional Header Image
typedef struct optional_header{
  uint16_t  magic;  
  uint8_t   majorLinkerVer;
  uint8_t   minorLinkerVer;
  uint32_t  sizeOfCode;
  uint32_t  sizeOfInitializedData;
  uint32_t  sizeOfUninitializedData;
  uint32_t  entryPoint;
  uint32_t  baseOfCode;
  uint32_t  baseOfData;
  uint64_t  imageBase;
  uint32_t  sectionAlignment;
  uint32_t  fileAlignment;
  uint16_t  majorOSVer;
  uint16_t  minorOSVer;
  uint16_t 	majorImageVer; 	
  uint16_t 	minorImageVer;	
  uint16_t 	majorSubsystemVer; 
  uint16_t 	minorSubsystemVer; 
  uint32_t 	win32VersionVal; 	
  uint32_t 	sizeOfImage; 		
  uint32_t 	sizeOfHeaders; 		
  uint32_t 	checkSum; 			
  uint16_t 	subsystem; 			
  uint16_t 	dllCharacteristics; 	
  uint64_t 	sizeOfStackReserve; 	
  uint64_t 	sizeOfStackCommit; 	
  uint64_t 	sizeOfHeapReserve; 	
  uint64_t 	sizeOfHeapCommit; 	
  uint32_t 	loaderFlags; 		
  uint32_t 	numberOfRvaAndSizes;
} optional_header;


// PE header
typedef struct pe_header{
  uint32_t   peOffset; 
  uint32_t   signature;   
  uint16_t   machine; 
  uint16_t   numberOfSections;
  uint32_t   timeStamp;
  uint32_t   symTablePtr;
  uint32_t   numberOfSym;
  uint16_t   optionalHeaderSize;
  uint16_t   characteristics;
  optional_header *optionalHeader;
} pe_header;

// DOS header
typedef struct dos_header{
  uint16_t magic;
  uint32_t e_lfanew;
  pe_header *pe;
}dos_header;

// functions to output PE info
void print_info(dos_header *dosHeader);
void print_characteristics(uint16_t ch);
void print_machine(uint16_t mach);
void print_magic(uint16_t magic);
void print_subsystem(uint16_t system);
void print_dllcharacteristics(uint16_t ch);

// functions to read from FILE stream
void      read_pe(char *filename, dos_header *dosHeader);
void      read_OpionalHeader(FILE *in);
char     *read_Sig(FILE *in);
uint32_t  read_elfnew(FILE *in);
uint16_t  read8_le(FILE *in);
uint16_t  read16_le(FILE *in);
uint32_t  read32_le(FILE *in);
uint64_t  read64_le(FILE *in);


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
#define OPTIONAL_IMAGE_PE32      0x10b
#define OPTIONAL_IMAGE_PE32_plus 0x20b


// Image subsystem
#define IMAGE_SUBSYSTEM_UNKNOWN   		  	0   		//  An unknown subsystem
#define IMAGE_SUBSYSTEM_NATIVE    		  	1   		//  Device drivers and native Windows processes
#define IMAGE_SUBSYSTEM_WINDOWS_GUI     	2  		 	//  The Windows graphical user interface (GUI) subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CUI     	3  		 	//  The Windows character subsystem
#define IMAGE_SUBSYSTEM_OS2_CUI     	  	5    		//  The OS/2 character subsystem
#define IMAGE_SUBSYSTEM_POSIX_CUI     		7    		//	The Posix character subsystem
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS    8  	    //  Native Win9x driver
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI   	9   		//  Windows CE
#define IMAGE_SUBSYSTEM_EFI_APPLICATION   10   		//  An Extensible Firmware Interface (EFI) application
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER    11  //  An EFI driver with boot services
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER     	  12  // 	An EFI driver with run-time services
#define IMAGE_SUBSYSTEM_EFI_ROM     		13      	    	//	An EFI ROM image
#define IMAGE_SUBSYSTEM_XBOX     			  14              //  XBOX
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    16  //  Windows boot application. 


// Characteristics
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA   0x0020   // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE      0x0040   // DLL can be relocated at load time.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY   0x0080   // Code Integrity checks are enforced.
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT         0x0100   // Image is NX compatible.
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION      0x0200   // Isolation aware, but do not isolate the image.
#define IMAGE_DLLCHARACTERISTICS_NO_SEH            0x0400   // Does not use structured exception (SE) handling. No SE handler may be called in this image.
#define IMAGE_DLLCHARACTERISTICS_NO_BIND           0x0800   // Do not bind the image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER      0x1000   // Image must execute in an AppContainer.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER        0x2000   // A WDM driver.
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF          0x4000   // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE   0x8000  // Terminal Server aware. 

#endif