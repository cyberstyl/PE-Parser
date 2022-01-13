// pe-interface.c:
//    implements functions that deals with PE structures
//    read PE and save information in a struct.
#include "pe_header.h"

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

void print_characteristics(uint16_t ch)
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
void print_magic(uint16_t magic)
{
  switch (magic)
  {
  case OPTIONAL_IMAGE_PE32:
    printf("0x%x (PE) \n", OPTIONAL_IMAGE_PE32);
    break;

  case OPTIONAL_IMAGE_PE32_plus:
    printf("0x%x (PE+) \n", OPTIONAL_IMAGE_PE32_plus);
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
    printf("     IMAGE_FILE_MACHINE_UNKNOWN\n");
    break;

  case IMAGE_FILE_MACHINE_IA64:
    printf("     IMAGE_FILE_MACHINE_IA64\n");
    break;

  case IMAGE_FILE_MACHINE_I386:
    printf("     IMAGE_FILE_MACHINE_I386\n");
    break;

  case IMAGE_FILE_MACHINE_AMD64:
    printf("     IMAGE_FILE_MACHINE_AMD64\n");
    break;

  case IMAGE_FILE_MACHINE_ARM:
    printf("     IMAGE_FILE_MACHINE_ARM\n");
    break;

  case IMAGE_FILE_MACHINE_ARM64:
    printf("     IMAGE_FILE_MACHINE_ARM64\n");
    break;

  case IMAGE_FILE_MACHINE_ARMNT:
    printf("     IMAGE_FILE_MACHINE_ARMNT\n");
    break;

  case IMAGE_FILE_MACHINE_EBC:
    printf("     IMAGE_FILE_MACHINE_EBC\n");
    break;

  default:
    break;
  }
}

uint16_t  read8_le(FILE *in){
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
  value = fgetc(in) | (fgetc(in)<<8) | (fgetc(in)<<16) | (fgetc(in)<<24) ;
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

void print_info(dos_header *dosHeader)
{
  pe_header *file;
  file = dosHeader->pe;
  
  printf("=== PE header information ===\n");
  // Signature
  printf("Signature:          0x%x (%c%c) \n",  file->signature, 
               (0xff & file->signature), 0xff & (file->signature>>8) );
  // Machine
  printf("Machine:       ");
  print_machine(file->machine);
  // Number of sections
  printf("number of sections:    %d\n", file->numberOfSections);
  // Size of optional header
  printf("Size of OpionalHeader: 0x%x\n", file->optionalHeaderSize);
  // Characteristics
  printf("Characteristics: \n");
  print_characteristics(file->characteristics);
  // Image Optional Header 
  printf("Magic:      ");
  print_magic(file->optionalHeader->magic);
  printf("MajorLinkerVersion:  0x%x\n", file->optionalHeader->majorLinkerVer);
  printf("MinorLinkerVersion:  0x%x\n", file->optionalHeader->minorLinkerVer);
  printf("SizeOfCode:       0x%x\n", file->optionalHeader->majorLinkerVer);
  printf("SizeOfInitializedData: 0x%x\n", file->optionalHeader->sizeOfInitializedData);
  printf("SizeOfUninitializedData: 0x%x\n", file->optionalHeader->sizeOfUninitializedData);
  printf("SizeOfCode:       0x%x\n", file->optionalHeader->majorLinkerVer);
}

void read_pe(char *filename, dos_header *dosHeader)
{
  FILE *in;
  in = fopen(filename, "rb");

  if(in == NULL)
  {
    perror("Can't open file, exiting\n");
    exit(-1);
  }

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
    dosHeader->pe->SymTablPtr         = read32_le(in);
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

    dosHeader->pe->optionalHeader->baseOfData       = read32_le(in);
    dosHeader->pe->optionalHeader->imageBase        = read32_le(in);
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
    dosHeader->pe->optionalHeader->sizeOfStackReserve= read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfStackCommit = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfHeapReserve = read32_le(in);
    dosHeader->pe->optionalHeader->sizeOfHeapCommit  = read32_le(in);
    dosHeader->pe->optionalHeader->loaderFlags       = read32_le(in);
    dosHeader->pe->optionalHeader->numberOfRvaAndSizes = read32_le(in);
  }


  fclose(in);
}