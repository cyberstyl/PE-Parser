

#include "headers.h"


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

  // printf("\n========================\n");
  // printf("Data Tables \n");
  // for(int i = 0; i < 15; i++)
  // {
  //     if(dosHeader->dataDirectory[i].virtualAddr == 0) continue;

  //     printf("%s:\n", dataTable[i]);
  //     printf("      Virtual Address: %x (offset: %x)\n", dosHeader->dataDirectory[i].virtualAddr,
  //                                        rva_to_offset(dosHeader->pe.numberOfSections, 
  //                                              dosHeader->dataDirectory[i].virtualAddr, 
  //                                              dosHeader->section_table) );

  //     printf("      Size:            %x\n",  dosHeader->dataDirectory[i].size);
  // }  

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
    // print_info(&dosHeader);
    print_clean(&dosHeader);
    
    // cleanup
    cleanup(&dosHeader);
    fclose(in);
  }
}

void print_clean(dos_header_t *dosHeader)
{

  printf("Magic bytes: \t\t%c%c\n", (0xff & dosHeader->magic), ( dosHeader->magic>>8) );
  printf("PE Offset    \t\t%X\n", dosHeader->e_lfanew);

  printf("\nPE header information\n");
  printf(" Signature:   \t\t0x%X (%c%c) \n",  dosHeader->pe.signature, 
               (0xff & dosHeader->pe.signature), 0xff & (dosHeader->pe.signature>>8) );

  printf(" Machine:  \t\t");
  print_machine(dosHeader->pe.machine);

  printf(" Sections: \t\t%d\n", dosHeader->pe.numberOfSections);
  printf(" Time Stamp: \t\t0x%X\n", dosHeader->pe.timeStamp);
  printf(" Symbol Table Pointer:  0x%X\n", dosHeader->pe.symTablePtr);
  printf(" Symbols:               %d\n", dosHeader->pe.numberOfSym);
  printf(" OpionalHeader Size:    %d (0x%X)\n", dosHeader->pe.optionalHeaderSize, 
                          dosHeader->pe.optionalHeaderSize);
  printf(" Characteristics:       0x%X\n", dosHeader->pe.characteristics);
  print_pe_characteristics(dosHeader->pe.characteristics);
  
  printf("\n=== Optional header standard fields ===\n");
  printf("Magic:      ");
  print_magic(dosHeader->pe.optionalHeader.magic);
  printf("MajorLinkerVersion:      0x%x\n", dosHeader->pe.optionalHeader.majorLinkerVer);
  printf("MinorLinkerVersion:      0x%x\n", dosHeader->pe.optionalHeader.minorLinkerVer);
  printf("SizeOfCode:              0x%x\n", dosHeader->pe.optionalHeader.sizeOfCode);
  printf("SizeOfInitializedData:   0x%x\n", dosHeader->pe.optionalHeader.sizeOfInitializedData);
  printf("SizeOfUninitializedData: 0x%x\n", dosHeader->pe.optionalHeader.sizeOfUninitializedData);
  printf("EntryPoint:              0x%x\n", dosHeader->pe.optionalHeader.entryPoint);
  printf("BaseOfCode:              0x%x\n", dosHeader->pe.optionalHeader.baseOfCode);

  printf("\n=== Optional header windows-specific fields ===\n");
  if(dosHeader->pe.optionalHeader.magic == OPTIONAL_IMAGE_PE32){
    printf("BaseOfData:            0x%x\n", dosHeader->pe.optionalHeader.baseOfData);
  }
  printf("ImageBase:               %p\n", (void*) dosHeader->pe.optionalHeader.imageBase);
  printf("SectionAlignment:        0x%x\n", dosHeader->pe.optionalHeader.sectionAlignment);
  printf("FileAlignment:           0x%x\n", dosHeader->pe.optionalHeader.fileAlignment);
  printf("MajorOperatingSystemVersion:  0x%x\n", dosHeader->pe.optionalHeader.majorOSVer);
  printf("MinorOperatingSystemVersion:  0x%x\n", dosHeader->pe.optionalHeader.minorOSVer);  
  printf("MajorImageVersion:            0x%x\n", dosHeader->pe.optionalHeader.majorImageVer);
  printf("MinorImageVersion:            0x%x\n", dosHeader->pe.optionalHeader.minorImageVer);
  printf("MajorSubsystemVersion:        0x%x\n", dosHeader->pe.optionalHeader.majorSubsystemVer);
  printf("MinorSubsystemVersion:        0x%x\n", dosHeader->pe.optionalHeader.minorSubsystemVer);
  printf("Win32VersionValue:            0x%x\n", dosHeader->pe.optionalHeader.win32VersionVal);
  printf("SizeOfImage:                  0x%x\n", dosHeader->pe.optionalHeader.sizeOfImage);
  printf("SizeOfHeaders:                0x%x\n", dosHeader->pe.optionalHeader.sizeOfHeaders);
  printf("CheckSum:                     0x%x\n", dosHeader->pe.optionalHeader.checkSum);
  //printf("Subsystem:  ");
}
