// pe-interface.c:
//    implements functions that deals with PE structures
//    read PE and save information in a struct
//
#include "pe_header.h"

// Disable warning for fopen() under visual studio
#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

// DataTable Types
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

uint32_t   read_elfnew(FILE *in)
{
  uint32_t value;
  if(fseek(in, 0x3c, SEEK_SET) != -1)
  {
    value = read32_le(in);
  }
  else
  {
    return 0;
  }
  return value;
}

void print_pe_characteristics(uint16_t ch)
{
  if( ch & (IMAGE_FILE_DLL) )
  {
    printf("     IMAGE_FILE_DLL \n");
  }
  if(ch & (IMAGE_FILE_EXECUTABLE_IMAGE) )
  {
    printf("     IMAGE_FILE_EXECUTABLE_IMAGE \n");
  }
  if(ch & (IMAGE_FILE_DEBUG_STRIPPED) )
  {
    printf("     IMAGE_FILE_DEBUG_STRIPPED\n");
  }
  if(ch & (IMAGE_FILE_RELOCS_STRIPPED) )
  {
    printf("     IMAGE_FILE_RELOCS_STRIPPED\n");
  }
  if(ch & (IMAGE_FILE_LINE_NUMS_STRIPPED) )
  {
    printf("     IMAGE_FILE_LINE_NUMS_STRIPPED\n");
  }
  if(ch & (IMAGE_FILE_LOCAL_SYMS_STRIPPED) )
  {
    printf("     IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
  }
  if(ch & (IMAGE_FILE_AGGRESSIVE_WS_TRIM) )
  {
    printf("     IMAGE_FILE_AGGRESSIVE_WS_TRIM\n");
  }
  if(ch & (IMAGE_FILE_LARGE_ADDRESS_AWARE) )
  {
    printf("     IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
  }
  if(ch & (IMAGE_FILE_BYTES_REVERSED_LO) )
  {
    printf("     IMAGE_FILE_BYTES_REVERSED_LO\n");
  }
  if(ch & (IMAGE_FILE_32BIT_MACHINE) )
  {
    printf("     IMAGE_FILE_32BIT_MACHINE\n");
  }
  if(ch & (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) )
  {
    printf("     IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP\n");
  }
  if(ch & (IMAGE_FILE_NET_RUN_FROM_SWAP) )
  {
    printf("     IMAGE_FILE_NET_RUN_FROM_SWAP\n");
  }
  if(ch & (IMAGE_FILE_SYSTEM) )
  {
    printf("     IMAGE_FILE_SYSTEM\n");
  }
  if(ch & (IMAGE_FILE_BYTES_REVERSED_HI) )
  {
    printf("     IMAGE_FILE_BYTES_REVERSED_HI\n");
  }
  if(ch & (IMAGE_FILE_UP_SYSTEM_ONLY) )
  {
    printf("     IMAGE_FILE_UP_SYSTEM_ONLY\n");
  }

}

void print_dllcharacteristics(uint16_t ch){
  if( ch & (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA ) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA  \n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE \n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_NX_COMPAT) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_NX_COMPAT\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_NO_ISOLATION\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_NO_SEH) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_NO_SEH\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_NO_BIND) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_NO_BIND\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_APPCONTAINER) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_APPCONTAINER\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_WDM_DRIVER\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_GUARD_CF) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_GUARD_CF\n");
  }
  if(ch & (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) )
  {
    printf("     IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE\n");
  }
}

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

void print_section_characteristics(uint32_t ch){
  for(int i = 0; i < 35; i++){
    if(ch & (section_flags_arr[i])){
      printf("          %s\n", section_flags_str[i]);
    }
  }
}


char *read_str(FILE *in, int count){
  char *ch = malloc(sizeof(char)*count);
  char str_ch[0];
  for(int i = 0; i < count; i++){
    str_ch[0] = fgetc(in);
    strcat(ch, str_ch);
  }
  return ch;
}

uint8_t  read8_le(FILE *in){
  uint8_t value;
  value = fgetc(in);
  return value;
}

uint16_t  read16_le(FILE *in)
{
  uint16_t value;
  value = fgetc(in) | (fgetc(in)<<8);
  return value;
}

uint32_t  read32_le(FILE *in)
{
  uint32_t value;
  value = fgetc(in) | (fgetc(in)<<8) | (fgetc(in)<<16) | (fgetc(in)<<24);
  return value;
}

uint64_t  read64_le(FILE *in)
{
  uint64_t value;
  value = (uint64_t)fgetc(in) | ((uint64_t)fgetc(in)<<8) |
          ((uint64_t)fgetc(in)<<16) | ((uint64_t)fgetc(in)<<24)
          | ( (uint64_t)fgetc(in)<<32) | ( (uint64_t)fgetc(in)<<40)
          | ( (uint64_t)fgetc(in)<<48) | ((uint64_t)fgetc(in)<<54);
  return value;
}

void print_info(char *argv, dos_header_t *dosHeader)
{
  pe_header_t *file;
  file = dosHeader->pe;
  
  printf("\nFile: %s\n", argv);
  printf("\n=== PE header information ===\n");
  // PE header
  printf("Signature:        0x%x (%c%c) \n",  file->signature, 
               (0xff & file->signature), 0xff & (file->signature>>8) );
  printf("Machine:       ");
  print_machine(file->machine);
  printf("number of sections:      %d\n", file->numberOfSections);
  printf("TimeDateStamp:           0x%x\n", file->timeStamp);
  printf("PointerToSymbolTable:    0x%x\n", file->symTablePtr);
  printf("NumberOfSymbols:         %d\n", file->numberOfSym);
  printf("Size of OpionalHeader:   0x%x\n", file->optionalHeaderSize);
  printf("Characteristics:         0x%x\n", file->characteristics);
  print_pe_characteristics(file->characteristics);

  // Image Optional Header 
  printf("\n=== Optional header standard fields ===\n");
  printf("Magic:      ");
  print_magic(file->optionalHeader->magic);
  printf("MajorLinkerVersion:      0x%x\n", file->optionalHeader->majorLinkerVer);
  printf("MinorLinkerVersion:      0x%x\n", file->optionalHeader->minorLinkerVer);
  printf("SizeOfCode:              0x%x\n", file->optionalHeader->sizeOfCode);
  printf("SizeOfInitializedData:   0x%x\n", file->optionalHeader->sizeOfInitializedData);
  printf("SizeOfUninitializedData: 0x%x\n", file->optionalHeader->sizeOfUninitializedData);
  printf("EntryPoint:       0x%x\n", file->optionalHeader->entryPoint);
  printf("BaseOfCode:       0x%x\n", file->optionalHeader->baseOfCode);

  printf("\n=== Optional header windows-specific fields ===\n");
  if(file->optionalHeader->magic == OPTIONAL_IMAGE_PE32){
    printf("BaseOfData:           0x%x\n", file->optionalHeader->baseOfData);
  }
  printf("ImageBase:              %p\n", (void*) file->optionalHeader->imageBase);
  printf("SectionAlignment:       0x%x\n", file->optionalHeader->sectionAlignment);
  printf("FileAlignment:          0x%x\n", file->optionalHeader->fileAlignment);
  printf("MajorOperatingSystemVersion:      0x%x\n", file->optionalHeader->majorOSVer);
  printf("MinorOperatingSystemVersion:      0x%x\n", file->optionalHeader->minorOSVer);  
  printf("MajorImageVersion:      0x%x\n", file->optionalHeader->majorImageVer);
  printf("MinorImageVersion:      0x%x\n", file->optionalHeader->minorImageVer);
  printf("MajorSubsystemVersion:  0x%x\n", file->optionalHeader->majorSubsystemVer);
  printf("MinorSubsystemVersion:  0x%x\n", file->optionalHeader->minorSubsystemVer);
  printf("Win32VersionValue:      0x%x\n", file->optionalHeader->win32VersionVal);
  printf("SizeOfImage:            0x%x\n", file->optionalHeader->sizeOfImage);
  printf("SizeOfHeaders:   0x%x\n", file->optionalHeader->sizeOfHeaders);
  printf("CheckSum:        0x%x\n", file->optionalHeader->checkSum);
  printf("Subsystem:  ");
  print_subsystem(file->optionalHeader->subsystem);
  printf("DllCharacteristics:        \n");
  print_dllcharacteristics(file->optionalHeader->dllCharacteristics);

  printf("SizeOfStackReserve:     %p\n", (void*) file->optionalHeader->sizeOfStackReserve);
  printf("SizeOfStackCommit:      %p\n", (void*) file->optionalHeader->sizeOfStackCommit);
  printf("SizeOfHeapReserve:      %p\n", (void*) file->optionalHeader->sizeOfHeapReserve);
  printf("SizeOfHeapCommit:       %p\n", (void*) file->optionalHeader->sizeOfHeapCommit);

  printf("LoaderFlags:            0x%x\n", file->optionalHeader->loaderFlags);
  printf("NumberOfRvaAndSizes:    0x%x\n", file->optionalHeader->numberOfRvaAndSizes);

  printf("\n========================\n");
  printf("Data Tables \n");
  for(int i = 0; i < 16; i++){
      printf("%s:\n", dataTable[i]);
      printf("      Virtual Address: %x\n",  dosHeader->pe->optionalHeader->dataDirectory[i].virtualAddr);
      printf("      Size:            %x\n",  dosHeader->pe->optionalHeader->dataDirectory[i].size);
  }  

  printf("\n========================\n");
  printf("Sections: \n");

  for(int i = 0; i < dosHeader->pe->numberOfSections ;i++ ){
      printf("   Name: %s\n", dosHeader->pe->section_table[i].name );
      printf("       VirtualAddress: %x\n", dosHeader->pe->section_table[i].virtualAddr );
      printf("       VirtualSize:    %x\n", dosHeader->pe->section_table[i].virtualSize );
      printf("       SizeOfRawData:  %x\n", dosHeader->pe->section_table[i].sizeOfRawData );
      printf("       PointerToRawData:   %x\n", dosHeader->pe->section_table[i].ptrToRawData );
      printf("       PointerToRelactons: %x\n", dosHeader->pe->section_table[i].ptrToReloc );
      printf("       PointerToLinenumbers:  %x\n", dosHeader->pe->section_table[i].ptrToLineNum );
      printf("       NumberOfRelocations:   %x\n", dosHeader->pe->section_table[i].numberOfReloc );
      printf("       NumberOfLinenumbers:   %x\n", dosHeader->pe->section_table[i].numberOfLineNum );
      printf("       Characteristics:   %x\n", dosHeader->pe->section_table[i].characteristics );
      print_section_characteristics(dosHeader->pe->section_table[i].characteristics);

      free(dosHeader->pe->section_table[i].name);
  }
  free(dosHeader->pe->section_table);
}

void read_pe(char *filename, dos_header_t *dosHeader)
{
  FILE *in = NULL;
  in = fopen(filename, "rb");

  if(in == NULL)
  {
    perror("Can't open file, exiting\n");
    exit(-1);
  }

  // TODO: read DOS header
  //
  //

  // reading e_lfnew value
  dosHeader->pe->peOffset = read_elfnew(in);

  // reading PE header from e_lfanew offset
  if(fseek(in, dosHeader->pe->peOffset, SEEK_SET) != -1)
  {
    // PE header
    dosHeader->pe->signature          = read32_le(in);
    dosHeader->pe->machine            = read16_le(in);
    dosHeader->pe->numberOfSections   = read16_le(in);
    dosHeader->pe->timeStamp          = read32_le(in);
    dosHeader->pe->symTablePtr         = read32_le(in);
    dosHeader->pe->numberOfSym        = read32_le(in);
    dosHeader->pe->optionalHeaderSize = read16_le(in);
    dosHeader->pe->characteristics    = read16_le(in);

    // optional header (Standard Fields)
    dosHeader->pe->optionalHeader->magic          = read16_le(in);
    dosHeader->pe->optionalHeader->majorLinkerVer = read8_le(in);
    dosHeader->pe->optionalHeader->minorLinkerVer = read8_le(in);
    dosHeader->pe->optionalHeader->sizeOfCode     = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfInitializedData    = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfUninitializedData  = read32_le(in);
    dosHeader->pe->optionalHeader->entryPoint = read32_le(in);
    dosHeader->pe->optionalHeader->baseOfCode = read32_le(in);

    if(dosHeader->pe->optionalHeader->magic == OPTIONAL_IMAGE_PE32_plus)
    {
      dosHeader->pe->optionalHeader->imageBase        = read64_le(in);
    } else {
      dosHeader->pe->optionalHeader->baseOfData       = read32_le(in);
      dosHeader->pe->optionalHeader->imageBase        = read32_le(in);
    }
    
    dosHeader->pe->optionalHeader->sectionAlignment = read32_le(in);
    dosHeader->pe->optionalHeader->fileAlignment    = read32_le(in);
    dosHeader->pe->optionalHeader->majorOSVer       = read16_le(in);
    dosHeader->pe->optionalHeader->minorOSVer       = read16_le(in);
    dosHeader->pe->optionalHeader->majorImageVer    = read16_le(in);
    dosHeader->pe->optionalHeader->minorImageVer    = read16_le(in);
    dosHeader->pe->optionalHeader->majorSubsystemVer = read16_le(in);
    dosHeader->pe->optionalHeader->minorSubsystemVer = read16_le(in);
    dosHeader->pe->optionalHeader->win32VersionVal   = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfImage       = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfHeaders     = read32_le(in);
    dosHeader->pe->optionalHeader->checkSum          = read32_le(in);
    dosHeader->pe->optionalHeader->subsystem         = read16_le(in);
    dosHeader->pe->optionalHeader->dllCharacteristics= read16_le(in);
    
    if(dosHeader->pe->optionalHeader->magic == OPTIONAL_IMAGE_PE32_plus)
    {
      dosHeader->pe->optionalHeader->sizeOfStackReserve= read64_le(in);
      dosHeader->pe->optionalHeader->sizeOfStackCommit = read64_le(in);
      dosHeader->pe->optionalHeader->sizeOfHeapReserve = read64_le(in);
      dosHeader->pe->optionalHeader->sizeOfHeapCommit  = read64_le(in);      
    } else {
      dosHeader->pe->optionalHeader->sizeOfStackReserve= read32_le(in);
      dosHeader->pe->optionalHeader->sizeOfStackCommit = read32_le(in);
      dosHeader->pe->optionalHeader->sizeOfHeapReserve = read32_le(in);
      dosHeader->pe->optionalHeader->sizeOfHeapCommit  = read32_le(in);
    }
    dosHeader->pe->optionalHeader->loaderFlags         = read32_le(in);
    dosHeader->pe->optionalHeader->numberOfRvaAndSizes = read32_le(in);
    
    for(int i = 0; i < 16; i++){
        dosHeader->pe->optionalHeader->dataDirectory[i].virtualAddr = read32_le(in);
        dosHeader->pe->optionalHeader->dataDirectory[i].size = read32_le(in);
    }
    
    dosHeader->pe->section_table = malloc(sizeof(section_table_t) * 
                         dosHeader->pe->numberOfSections);
    for(int i = 0; i < dosHeader->pe->numberOfSections; i++){
        dosHeader->pe->section_table[i].name = read_str(in, 8);
        dosHeader->pe->section_table[i].virtualSize = read32_le(in);
        dosHeader->pe->section_table[i].virtualAddr = read32_le(in);
        dosHeader->pe->section_table[i].sizeOfRawData = read32_le(in);
        dosHeader->pe->section_table[i].ptrToRawData = read32_le(in);
        dosHeader->pe->section_table[i].ptrToReloc = read32_le(in);
        dosHeader->pe->section_table[i].ptrToLineNum= read32_le(in);
        dosHeader->pe->section_table[i].numberOfReloc = read16_le(in);
        dosHeader->pe->section_table[i].numberOfLineNum = read16_le(in);
        dosHeader->pe->section_table[i].characteristics = read32_le(in);
    }


  }


  fclose(in);
}