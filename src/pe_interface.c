// pe-interface.c:
//    implements functions that deals with PE structures
//    read PE and save information in a struct
//
#include "pe_header.h"

// Data Directories Types
char dataTable[][25] = { "Export Table",
                      "Import Table",
                      "Resource Table",
                      "Exception Table",
                      "Certificate Table",
                      "Base Relocation Table",
                      "Debug",
                      "Architecture",
                      "Global Ptr",
                      "TLS Table",
                      "Load Config Table",
                      "Bound Import",
                      "IAT",
                      "Delay Import Descriptor",
                      "CLR Runtime Header",
                      "Reserved, must be zero"};


// header section types
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

char section_flags_str[][33] = { "IMAGE_SCN_TYPE_NO_PAD",
"IMAGE_SCN_CNT_CODE", "IMAGE_SCN_CNT_INITIALIZED_DATA",
"IMAGE_SCN_CNT_UNINITIALIZED_ DATA", "IMAGE_SCN_LNK_OTHER",
"IMAGE_SCN_LNK_INFO", "IMAGE_SCN_LNK_REMOVE",
"IMAGE_SCN_LNK_COMDAT", "IMAGE_SCN_GPREL",
"IMAGE_SCN_MEM_PURGEABLE", "IMAGE_SCN_MEM_16BIT",
"IMAGE_SCN_MEM_LOCKED", "IMAGE_SCN_MEM_PRELOAD",
"IMAGE_SCN_ALIGN_1BYTES", "IMAGE_SCN_ALIGN_2BYTES",
"IMAGE_SCN_ALIGN_4BYTES", "IMAGE_SCN_ALIGN_8BYTES",
"IMAGE_SCN_ALIGN_16BYTES", "IMAGE_SCN_ALIGN_32BYTES",
"IMAGE_SCN_ALIGN_64BYTES", "IMAGE_SCN_ALIGN_128BYTES",
"IMAGE_SCN_ALIGN_256BYTES", "IMAGE_SCN_ALIGN_512BYTES",
"IMAGE_SCN_ALIGN_1024BYTES", "IMAGE_SCN_ALIGN_2048BYTES",
"IMAGE_SCN_ALIGN_4096BYTES", "IMAGE_SCN_ALIGN_8192BYTES",
"IMAGE_SCN_LNK_NRELOC_OVFL", "IMAGE_SCN_MEM_DISCARDABLE",
"IMAGE_SCN_MEM_NOT_CACHED", "IMAGE_SCN_MEM_NOT_PAGED",
"IMAGE_SCN_MEM_SHARED", "IMAGE_SCN_MEM_EXECUTE",
"IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"};

uint32_t section_flags_arr[] = {0x00000008,
0x00000020, 0x00000040, 0x00000080, 0x00000100,
0x00000200, 0x00000800, 0x00001000, 0x00008000,
0x00020000, 0x00020000, 0x00040000, 0x00080000,
0x00100000, 0x00200000, 0x00300000, 0x00400000,
0x00500000, 0x00600000, 0x00700000, 0x00800000,
0x00900000, 0x00A00000, 0x00B00000, 0x00C00000,
0x00D00000, 0x00E00000, 0x01000000, 0x02000000,
0x04000000, 0x08000000, 0x10000000, 0x20000000,
0x40000000, 0x80000000};

// Image PE File type
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
char image_file_str[][34] = {"IMAGE_FILE_RELOCS_STRIPPED", "IMAGE_FILE_EXECUTABLE_IMAGE", 
                      "IMAGE_FILE_LINE_NUMS_STRIPPED", "IMAGE_FILE_LOCAL_SYMS_STRIPPED", 
                      "IMAGE_FILE_AGGRESSIVE_WS_TRIM", "IMAGE_FILE_LARGE_ADDRESS_AWARE", 
                      "IMAGE_FILE_BYTES_REVERSED_LO", "IMAGE_FILE_32BIT_MACHINE", 
                      "IMAGE_FILE_DEBUG_STRIPPED","IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 
                      "IMAGE_FILE_NET_RUN_FROM_SWAP", "IMAGE_FILE_SYSTEM", "IMAGE_FILE_DLL", 
                      "IMAGE_FILE_UP_SYSTEM_ONLY", "IMAGE_FILE_BYTES_REVERSED_HI"};

uint16_t image_file_arr[] = {0x0001, 0x0002, 0x0004,
                    0x0008, 0x0010, 0x0020, 0x0080, 0x0100,
                    0x0200, 0x0400, 0x0800, 0x1000, 0x2000,
                    0x4000, 0x8000};

// DLL Characteristics
char image_dll_str[][46] = {"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
                      "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                      "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
                      "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",		
                      "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
                      "IMAGE_DLLCHARACTERISTICS_NO_SEH",  		
                      "IMAGE_DLLCHARACTERISTICS_NO_BIND",
                      "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
                      "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
                      "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                      "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"};

uint16_t image_dll_arr[] = {0x0020, 0x0040, 0x0080, 0x0100,
0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000};


//-------------------------------------------
// A reminder
// A byte is       8 bits, 
// a word is       2 bytes (16 bits), 
// a doubleword is 4 bytes (32 bits), 
// a quadword is   8 bytes (64 bits).
//-------------------------------------------

// read_str(): reads a 'count' of characters from a file
// arguments: FILE stream to read from, count of characters to read
// returns: pointer to a string of characters.
char *read_str(FILE *in, int count)
{
  char *ch_ptr = malloc(sizeof(char)*count);
  char byte[0];
  for(int i = 0; i < count; i++)
  {
    byte[0] = fgetc(in);
    strcat(ch_ptr, byte);
  }
  return ch_ptr;
}

// read8_le(): reads an 8bit integer
// arguments: a file stream to read from
// return: an 8 bit integer
uint8_t  read8_le(FILE *in)
{
  return fgetc(in);
}

// read16_le(): reads an 16bit little-endian integer
// arguments: a file stream to read from
// return: an 16 bit integer
uint16_t  read16_le(FILE *in)
{
  return (fgetc(in) | (fgetc(in)<<8));
}

// read32_le(): reads an 32bit little-endian integer
// arguments: a file stream to read from
// return: an 32 bit integer
uint32_t  read32_le(FILE *in)
{
  uint32_t value;
  value = fgetc(in) | (fgetc(in)<<8) | (fgetc(in)<<16) 
          | (fgetc(in)<<24);
  return value;
}

// read64_le(): reads an 64bit little-endian integer
// arguments: a file stream to read from
// return: an 64 bit integer
uint64_t  read64_le(FILE *in)
{
  uint64_t value;
  value = (uint64_t)fgetc(in) | ((uint64_t)fgetc(in)<<8) |
          ((uint64_t)fgetc(in)<<16) | ((uint64_t)fgetc(in)<<24)
          | ( (uint64_t)fgetc(in)<<32) | ( (uint64_t)fgetc(in)<<40)
          | ( (uint64_t)fgetc(in)<<48) | ((uint64_t)fgetc(in)<<54);
  return value;
}


// cleanup(): a function to clean allocated memory inside structs
// arguments: a pointer to Dos header object
// returns: none
void cleanup(dos_header_t *dosHeader)
{
  free(dosHeader->dataDirectory);
  for(int i = 0; i < dosHeader->pe.numberOfSections; i++)
  {
    free(dosHeader->section_table[i].name);
  }
  free(dosHeader->section_table);
}

// rva_to_offset(): converts an RVA address to a file offset.
// arguments: the number of sections, rva and pointer to sections
// returns: converted file offset, or 0 if rva is 0, or -1 if it fails.
unsigned int rva_to_offset(int numberOfSections, 
                           unsigned int rva, 
                           section_table_t *sections)
{
  if(rva == 0) return 0;
  unsigned int sumAddr;

  for (int idx = 0; idx < numberOfSections; idx++) 
  {
    sumAddr = sections[idx].virtualAddr + sections[idx].sizeOfRawData;
    
    if ( rva >= sections[idx].virtualAddr && (rva <= sumAddr) )
    {
      return  sections[idx].ptrToRawData + (rva - sections[idx].virtualAddr);
    }
  }
  return -1;
}

// print_pe_characteristics(): takes in a flags characteristics and prints them
// arguments: a WORD sized integer
// returns: none
void print_pe_characteristics(uint16_t ch)
{
  for(int idx = 0; idx < 15; idx++)
  {
    if(ch & (image_file_arr[idx]))
     printf("     %s\n", image_file_str[idx]);
  }
}

// print_dllcharacteristics(): takes in a flags characteristics and prints them
// arguments: a WORD sized integer
// returns: none
void print_dllcharacteristics(uint16_t ch)
{
  for(int idx = 0; idx < 11; idx++)
  {
    if(ch & (image_dll_arr[idx]))
     printf("     %s\n", image_dll_str[idx]);
  }
}

// print_magic(): prints the type of a PE image
// arguments: a WORD sized integer
// returns: none
void print_magic(uint16_t magic)
{
  switch (magic)
  {
  case OPTIONAL_IMAGE_PE32:
    printf("%x (PE) \n", OPTIONAL_IMAGE_PE32);
    break;

  case OPTIONAL_IMAGE_PE32_plus:
    printf("%x (PE+) \n", OPTIONAL_IMAGE_PE32_plus);
    break;

  default:
    printf("0 (Error) \n");
    break;
  }
}

// print_machine(): prints the machine type of a PE image
// arguments: a WORD sized integer
// returns: none
void print_machine(uint16_t mach)
{
  switch (mach)
  {
  case IMAGE_FILE_MACHINE_UNKNOWN:
    printf("   (%x)  IMAGE_FILE_MACHINE_UNKNOWN\n", IMAGE_FILE_MACHINE_UNKNOWN);
    break;

  case IMAGE_FILE_MACHINE_IA64:
    printf("   (%x)  IMAGE_FILE_MACHINE_IA64\n", IMAGE_FILE_MACHINE_IA64);
    break;

  case IMAGE_FILE_MACHINE_I386:
    printf("   (%x)  IMAGE_FILE_MACHINE_I386\n", IMAGE_FILE_MACHINE_I386);
    break;

  case IMAGE_FILE_MACHINE_AMD64:
    printf("   (%x)  IMAGE_FILE_MACHINE_AMD64\n", IMAGE_FILE_MACHINE_AMD64);
    break;

  case IMAGE_FILE_MACHINE_ARM:
    printf("   (%x)  IMAGE_FILE_MACHINE_ARM\n", IMAGE_FILE_MACHINE_ARM);
    break;

  case IMAGE_FILE_MACHINE_ARM64:
    printf("   (%x)  IMAGE_FILE_MACHINE_ARM64\n", IMAGE_FILE_MACHINE_ARM64);
    break;

  case IMAGE_FILE_MACHINE_ARMNT:
    printf("   (%x)  IMAGE_FILE_MACHINE_ARMNT\n", IMAGE_FILE_MACHINE_ARM64);
    break;

  case IMAGE_FILE_MACHINE_EBC:
    printf("   (%x)  IMAGE_FILE_MACHINE_EBC\n", IMAGE_FILE_MACHINE_EBC);
    break;

  default:
    break;
  }
}

// print_subsystem(): prints the subsystem of a PE
// arguments: a WORD sized integer
// returns: none
void print_subsystem(uint16_t system){
  switch (system)
  {
  case IMAGE_SUBSYSTEM_UNKNOWN:
    printf("  (%x)   IMAGE_SUBSYSTEM_UNKNOWN\n", IMAGE_SUBSYSTEM_UNKNOWN);
    break;

  case IMAGE_SUBSYSTEM_NATIVE:
    printf("  (%x)   IMAGE_SUBSYSTEM_NATIVE\n", IMAGE_SUBSYSTEM_NATIVE);
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_GUI:
    printf("  (%x)   IMAGE_SUBSYSTEM_WINDOWS_GUI\n", IMAGE_SUBSYSTEM_WINDOWS_GUI);
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_CUI:
    printf("  (%x)   IMAGE_SUBSYSTEM_WINDOWS_CUI\n", IMAGE_SUBSYSTEM_WINDOWS_CUI);
    break;

  case IMAGE_SUBSYSTEM_OS2_CUI:
    printf("     IMAGE_SUBSYSTEM_OS2_CUI\n");
    break;

  case IMAGE_SUBSYSTEM_POSIX_CUI:
    printf("     IMAGE_SUBSYSTEM_POSIX_CUI\n");
    break;

  case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
    printf("     IMAGE_SUBSYSTEM_NATIVE_WINDOWS\n");
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
    printf("     IMAGE_SUBSYSTEM_WINDOWS_CE_GUI\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_APPLICATION:
    printf("     IMAGE_SUBSYSTEM_EFI_APPLICATION\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    printf("     IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    printf("     IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER\n");
    break;

  case IMAGE_SUBSYSTEM_EFI_ROM:
    printf("     IMAGE_SUBSYSTEM_EFI_ROM\n");
    break;

  case IMAGE_SUBSYSTEM_XBOX:
    printf("     IMAGE_SUBSYSTEM_XBOX\n");
    break;

  case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
    printf("     IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION\n");
    break;

  default:
    break;
  }
}

// print_section_characteristics(): prints the flags set on a section
// arguments: a DWORD sized integer
// returns: none
void print_section_characteristics(uint32_t ch){
  for(int i = 0; i < 35; i++)
  {
    if(ch & (section_flags_arr[i]))
    {
      printf("          %s\n", section_flags_str[i]);
    }
  }
}

// printf_info(): a function to print out all content of parsed PE file
// arguments: takes a DOS header structure to read from.
// return: none
void print_info(dos_header_t *dosHeader)
{
  printf("DOS Magic bytes: %c%c\n", (0xff & dosHeader->magic), ( dosHeader->magic>>8) );
  printf("PE Offset:       %x\n", dosHeader->e_lfanew);

  printf("\n=== PE header information ===\n");
  printf("Signature:        0x%x (%c%c) \n",  dosHeader->pe.signature, 
               (0xff & dosHeader->pe.signature), 0xff & (dosHeader->pe.signature>>8) );
  printf("Machine:       ");
  print_machine(dosHeader->pe.machine);
  printf("number of sections:      %d\n", dosHeader->pe.numberOfSections);
  printf("TimeDateStamp:           0x%x\n", dosHeader->pe.timeStamp);
  printf("PointerToSymbolTable:    0x%x\n", dosHeader->pe.symTablePtr);
  printf("NumberOfSymbols:         %d\n", dosHeader->pe.numberOfSym);
  printf("Size of OpionalHeader:   0x%x\n", dosHeader->pe.optionalHeaderSize);
  printf("Characteristics:         0x%x\n", dosHeader->pe.characteristics);
  print_pe_characteristics(dosHeader->pe.characteristics);
  
  printf("\n=== Optional header standard fields ===\n");
  printf("Magic:      ");
  print_magic(dosHeader->pe.optionalHeader.magic);
  printf("MajorLinkerVersion:      0x%x\n", dosHeader->pe.optionalHeader.majorLinkerVer);
  printf("MinorLinkerVersion:      0x%x\n", dosHeader->pe.optionalHeader.minorLinkerVer);
  printf("SizeOfCode:              0x%x\n", dosHeader->pe.optionalHeader.sizeOfCode);
  printf("SizeOfInitializedData:   0x%x\n", dosHeader->pe.optionalHeader.sizeOfInitializedData);
  printf("SizeOfUninitializedData: 0x%x\n", dosHeader->pe.optionalHeader.sizeOfUninitializedData);
  printf("EntryPoint:       0x%x\n", dosHeader->pe.optionalHeader.entryPoint);
  printf("BaseOfCode:       0x%x\n", dosHeader->pe.optionalHeader.baseOfCode);

  printf("\n=== Optional header windows-specific fields ===\n");
  if(dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32){
    printf("BaseOfData:           0x%x\n", dosHeader->pe.optionalHeader.baseOfData);
  }
  printf("ImageBase:              %p\n", (void*) dosHeader->pe.optionalHeader.imageBase);
  printf("SectionAlignment:       0x%x\n", dosHeader->pe.optionalHeader.sectionAlignment);
  printf("FileAlignment:          0x%x\n", dosHeader->pe.optionalHeader.fileAlignment);
  printf("MajorOperatingSystemVersion:      0x%x\n", dosHeader->pe.optionalHeader.majorOSVer);
  printf("MinorOperatingSystemVersion:      0x%x\n", dosHeader->pe.optionalHeader.minorOSVer);  
  printf("MajorImageVersion:      0x%x\n", dosHeader->pe.optionalHeader.majorImageVer);
  printf("MinorImageVersion:      0x%x\n", dosHeader->pe.optionalHeader.minorImageVer);
  printf("MajorSubsystemVersion:  0x%x\n", dosHeader->pe.optionalHeader.majorSubsystemVer);
  printf("MinorSubsystemVersion:  0x%x\n", dosHeader->pe.optionalHeader.minorSubsystemVer);
  printf("Win32VersionValue:      0x%x\n", dosHeader->pe.optionalHeader.win32VersionVal);
  printf("SizeOfImage:            0x%x\n", dosHeader->pe.optionalHeader.sizeOfImage);
  printf("SizeOfHeaders:   0x%x\n", dosHeader->pe.optionalHeader.sizeOfHeaders);
  printf("CheckSum:        0x%x\n", dosHeader->pe.optionalHeader.checkSum);
  printf("Subsystem:  ");
  print_subsystem(dosHeader->pe.optionalHeader.subsystem);
  printf("DllCharacteristics:        \n");
  print_dllcharacteristics(dosHeader->pe.optionalHeader.dllCharacteristics);

  printf("SizeOfStackReserve:     %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfStackReserve);
  printf("SizeOfStackCommit:      %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfStackCommit);
  printf("SizeOfHeapReserve:      %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfHeapReserve);
  printf("SizeOfHeapCommit:       %p\n", (void*) dosHeader->pe.optionalHeader.sizeOfHeapCommit);

  printf("LoaderFlags:            0x%x\n", dosHeader->pe.optionalHeader.loaderFlags);
  printf("NumberOfRvaAndSizes:    0x%x\n", dosHeader->pe.optionalHeader.numberOfRvaAndSizes);

  printf("\n========================\n");
  printf("Data Tables \n");
  for(int i = 0; i < 15; i++)
  {
      if(dosHeader->dataDirectory[i].virtualAddr == 0) continue;

      printf("%s:\n", dataTable[i]);
      printf("      Virtual Address: %x (offset: %x)\n", dosHeader->dataDirectory[i].virtualAddr,
                                         rva_to_offset(dosHeader->pe.numberOfSections, 
                                               dosHeader->dataDirectory[i].virtualAddr, 
                                               dosHeader->section_table) );

      printf("      Size:            %x\n",  dosHeader->dataDirectory[i].size);
  }  

  printf("\n========================\n");
  printf("Sections: \n");

  for(int i = 0; i < dosHeader->pe.numberOfSections ;i++ )
  {
      printf("   Name: %s\n", dosHeader->section_table[i].name );
      printf("       VirtualAddress: %x\n", dosHeader->section_table[i].virtualAddr );
      printf("       VirtualSize:    %x\n", dosHeader->section_table[i].virtualSize );
      printf("       SizeOfRawData:  %x\n", dosHeader->section_table[i].sizeOfRawData );
      printf("       PointerToRawData:   %x\n", dosHeader->section_table[i].ptrToRawData );
      printf("       PointerToRelactons: %x\n", dosHeader->section_table[i].ptrToReloc );
      printf("       PointerToLinenumbers:  %x\n", dosHeader->section_table[i].ptrToLineNum );
      printf("       NumberOfRelocations:   %x\n", dosHeader->section_table[i].numberOfReloc );
      printf("       NumberOfLinenumbers:   %x\n", dosHeader->section_table[i].numberOfLineNum );
      printf("       Characteristics:   %x\n", dosHeader->section_table[i].characteristics );
      print_section_characteristics(dosHeader->section_table[i].characteristics);
  }
}

// read_dos(): reads DOS Header values from a file
// arguments: a FILE stream object, a pointer to a Dos header struct
// returns: none
void read_dos(FILE *in, dos_header_t *dosHeader)
{
  // Reading DOS Header
  dosHeader->magic      = read16_le(in);
  dosHeader->e_cblp     = read16_le(in);
  dosHeader->e_cp       = read16_le(in);
  dosHeader->e_crlc     = read16_le(in);
  dosHeader->e_cparhdr  = read16_le(in);
  dosHeader->e_minalloc = read16_le(in);
  dosHeader->e_maxalloc = read16_le(in);
  dosHeader->e_ss       = read16_le(in);
  dosHeader->e_sp       = read16_le(in);
  dosHeader->e_csum     = read16_le(in);
  dosHeader->e_ip       = read16_le(in);
  dosHeader->e_cs       = read16_le(in);
  dosHeader->e_lfarlc   = read16_le(in);
  dosHeader->e_ovno     = read16_le(in);

  // some of the next fields are reserved/aren't used
  dosHeader->e_res      = read64_le(in);
  dosHeader->e_oemid    = read16_le(in);
  dosHeader->e_oeminfo  = read16_le(in);
  dosHeader->e_res2     = read64_le(in); // this is repeated on purpose since
  dosHeader->e_res2     = read64_le(in); // most PE files have this field as zero
  dosHeader->e_res2     = read32_le(in); // i'll fix it later.
  /////////////////////////////////////////////
  dosHeader->e_lfanew   = read32_le(in);
}


// read_pe(): reads in PE header information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_pe(FILE *in, dos_header_t *dosHeader)
{

  if( fseek(in, dosHeader->e_lfanew, SEEK_SET) == -1)
  {  
    printf("Error during file reading.\n");
    exit(-1);
  } 

  // PE header
  dosHeader->pe.signature          = read32_le(in);
  dosHeader->pe.machine            = read16_le(in);
  dosHeader->pe.numberOfSections   = read16_le(in);
  dosHeader->pe.timeStamp          = read32_le(in);
  dosHeader->pe.symTablePtr        = read32_le(in);
  dosHeader->pe.numberOfSym        = read32_le(in);
  dosHeader->pe.optionalHeaderSize = read16_le(in);
  dosHeader->pe.characteristics    = read16_le(in);
  
  // optional header (Standard Fields)
  dosHeader->pe.optionalHeader.magic          = read16_le(in);
  dosHeader->pe.optionalHeader.majorLinkerVer = read8_le(in);
  dosHeader->pe.optionalHeader.minorLinkerVer = read8_le(in);
  dosHeader->pe.optionalHeader.sizeOfCode     = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfInitializedData    = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfUninitializedData  = read32_le(in);
  dosHeader->pe.optionalHeader.entryPoint = read32_le(in);
  dosHeader->pe.optionalHeader.baseOfCode = read32_le(in);

  // Optional Header Windows-Specific Fields 
  if(dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32_plus)
  {
    dosHeader->pe.optionalHeader.imageBase        = read64_le(in);
  } else {
    dosHeader->pe.optionalHeader.baseOfData       = read32_le(in);
    dosHeader->pe.optionalHeader.imageBase        = read32_le(in);
  }
  
  dosHeader->pe.optionalHeader.sectionAlignment  = read32_le(in);
  dosHeader->pe.optionalHeader.fileAlignment     = read32_le(in);
  dosHeader->pe.optionalHeader.majorOSVer        = read16_le(in);
  dosHeader->pe.optionalHeader.minorOSVer        = read16_le(in);
  dosHeader->pe.optionalHeader.majorImageVer     = read16_le(in);
  dosHeader->pe.optionalHeader.minorImageVer     = read16_le(in);
  dosHeader->pe.optionalHeader.majorSubsystemVer = read16_le(in);
  dosHeader->pe.optionalHeader.minorSubsystemVer = read16_le(in);
  dosHeader->pe.optionalHeader.win32VersionVal   = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfImage       = read32_le(in);
  dosHeader->pe.optionalHeader.sizeOfHeaders     = read32_le(in);
  dosHeader->pe.optionalHeader.checkSum          = read32_le(in);
  dosHeader->pe.optionalHeader.subsystem         = read16_le(in);
  dosHeader->pe.optionalHeader.dllCharacteristics= read16_le(in);
  
  if(dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32_plus)
  {
    dosHeader->pe.optionalHeader.sizeOfStackReserve= read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfStackCommit = read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapReserve = read64_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapCommit  = read64_le(in);      
  } else {
    dosHeader->pe.optionalHeader.sizeOfStackReserve= read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfStackCommit = read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapReserve = read32_le(in);
    dosHeader->pe.optionalHeader.sizeOfHeapCommit  = read32_le(in);
  }
  dosHeader->pe.optionalHeader.loaderFlags         = read32_le(in);
  dosHeader->pe.optionalHeader.numberOfRvaAndSizes = read32_le(in);
}

// read_dataDir(): reads in Data Directories information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_dataDir(FILE *in, dos_header_t * dosHeader)
{
  int dirs = dosHeader->pe.optionalHeader.numberOfRvaAndSizes;

  // Reading Data Directories
  dosHeader->dataDirectory = malloc(sizeof(data_directory_t) * dirs );

  for(int idx = 0; idx < dirs ; idx++)
  {
    dosHeader->dataDirectory[idx].virtualAddr = read32_le(in);
    dosHeader->dataDirectory[idx].size = read32_le(in);
  }
}

// read_sections(): reads in sections information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_sections(FILE *in, dos_header_t *dosHeader)
{
  int sections = dosHeader->pe.numberOfSections;
  // Reading Sections data
  dosHeader->section_table = malloc(sizeof(section_table_t) * sections  );

  for(int idx = 0; idx < sections; idx++)
  {
    dosHeader->section_table[idx].name            = read_str(in, 8);
    dosHeader->section_table[idx].virtualSize     = read32_le(in);
    dosHeader->section_table[idx].virtualAddr     = read32_le(in);
    dosHeader->section_table[idx].sizeOfRawData   = read32_le(in);
    dosHeader->section_table[idx].ptrToRawData    = read32_le(in);
    dosHeader->section_table[idx].ptrToReloc      = read32_le(in);
    dosHeader->section_table[idx].ptrToLineNum    = read32_le(in);
    dosHeader->section_table[idx].numberOfReloc   = read16_le(in);
    dosHeader->section_table[idx].numberOfLineNum = read16_le(in);
    dosHeader->section_table[idx].characteristics = read32_le(in);
  }

}

// read_exportDir(): reads in Export directory information
// arguments: a pointer to a FILE stream, and a DOS header structure
// return: none
void read_exportDir(FILE *in, dos_header_t *dosHeader)
{
    // dosHeader->exportDir.exportFlags = read32_le(in);
    // dosHeader->exportDir.timeStamp = read32_le(in);
    // dosHeader->exportDir.majorVer  = read16_le(in);
    // dosHeader->exportDir.minorVer  = read16_le(in);
    // dosHeader->exportDir.nameRVA   = read32_le(in);
    // dosHeader->exportDir.ordBase   = read32_le(in);
    // dosHeader->exportDir.addrTableEntries = read32_le(in);
    // dosHeader->exportDir.numberOfNamePointers = read32_le(in);
    // dosHeader->exportDir.exportAddrTableRVA = read32_le(in);
    // dosHeader->exportDir.namePtrRVA = read32_le(in);
    // dosHeader->exportDir.ordTableRVA = read32_le(in);
}


void load_file(int argc, char *argv[])
{
  FILE *in;
  dos_header_t dosHeader;

  for(int idx = 1; idx < argc; idx++)
  {
    in = fopen(argv[idx], "rb");
    if(in == NULL)
    {
      printf("Can't open '%s' file, exiting\n", argv[idx]);
      continue;
    }      

    // read headers
    read_dos(in, &dosHeader);    
    read_pe(in, &dosHeader);
    read_dataDir(in, &dosHeader);
    read_sections(in, &dosHeader);
    read_exportDir(in, &dosHeader);
    

    // test printing information
    printf("showing file: %s \n\n", argv[idx]);
    print_info(&dosHeader);
    
    // cleanup
    cleanup(&dosHeader);
    fclose(in);
  }
}