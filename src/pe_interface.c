// pe-interface.c:
//    implements functions that deals with PE structures
//    read PE and save information in a struct.
#include "pe_header.h"

uint8_t   get_elfnew(FILE *in){
  uint8_t value;
  if(fseek(in, 0x3c, SEEK_SET) != -1)
  {
    value = get32_le(in);
  } else {
    return 0;
  }
  return value;
}

char *get_Sig(FILE *in){
  char *ch;
  ch = malloc( sizeof(char) * 4);
  ch[0] = fgetc(in);
  ch[1] = fgetc(in);
  ch[2] = fgetc(in);
  ch[3] = fgetc(in);
  return ch;
}

uint16_t  get16_le(FILE *in){
  uint16_t value;
  value = fgetc(in) | (fgetc(in)<<8);
  return value;
}

uint32_t  get32_le(FILE *in){
  uint32_t value;
  value = fgetc(in) | (fgetc(in)<<8) | (fgetc(in)<<16) | (fgetc(in)<<24) ;
  return value;
}

uint64_t  get64_le(FILE *in){
  uint64_t value;
  value = (uint64_t)fgetc(in) | ((uint64_t)fgetc(in)<<8) |
                      ((uint64_t)fgetc(in)<<16) | ((uint64_t)fgetc(in)<<24)
                      | ( (uint64_t)fgetc(in)<<32) | ( (uint64_t)fgetc(in)<<40)
                      | ( (uint64_t)fgetc(in)<<48) | ((uint64_t)fgetc(in)<<54);
  return value;
}

void print_info(pe_file *file)
{
  printf("Signature:             %s\n", file->sig);
  switch (file->machine)
  {
  case IMAGE_FILE_MACHINE_I386:
    printf("Machine:               Intel 386 \n");
    break;
  case IMAGE_FILE_MACHINE_AMD64:
    printf("Machine:               x64 \n");
    break;

  default:
    printf("Machine:             unknown \n");
  }
  printf("Number of Sections:    %d\n", file->sections);
  printf("OptionalHeader size:   %d (0x%x)\n",
         file->optionalHeaderSize, file->optionalHeaderSize);

  printf("Characteristics:       ");
  if( file->characteristics & (IMAGE_FILE_DLL) )
  {
    printf("DLL \n");
  }
  else if(file->characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE) )
  {
    printf("EXE \n");
  }
  if(file->characteristics & (IMAGE_FILE_DEBUG_STRIPPED) )
  {
    printf("                       Stripped Debug info\n");
  }


  switch (file->optionalImage)
  {
  case OPTIONAL_IMAGE_32:
    printf("Optional Image header: 0x%x PE (32 bit) \n",
           file->optionalImage);
    break;
  case OPTIONAL_IMAGE_64:
    printf("Optional Image header: 0x%x PE+ (64 bit) \n",
           file->optionalImage);
    break;

  default:
    break;
  }

  printf("Address of EntryPoint: 0x%X (%p) \n", file->EntryPoint,
         (void *) ((file->EntryPoint) + (file->ImageBase) ));
  printf("Image Base:            %p \n", (void *) file->ImageBase);
}


void read_pe(char *filename, pe_file *file)
{
  FILE *in;
  in = fopen(filename, "rb");
  if(in == NULL)
  {
    perror("Can't open file, exiting\n");
    exit(-1);
  }
  // reading e_lfnew value
  file->PE_offset = get_elfnew(in);

  // PE's signature, Machine and number of sections
  if(fseek(in, file->PE_offset, SEEK_SET) != -1)
  {
    file->sig = get_Sig(in);
    file->machine = get16_le(in);
    file->sections = get16_le(in);
  }

// SizeOfOptionalHeader and Characteristics
  if(fseek(in, file->PE_offset+20, SEEK_SET) != -1)
  {
    file->optionalHeaderSize = get16_le(in);;
    file->characteristics = get16_le(in);;
    file->optionalImage = get16_le(in);;
  }

  // reading Address of EntryPoint and ImageBase
  if(fseek(in, 14, SEEK_CUR) != -1)
  {
    file->EntryPoint = get32_le(in);
  }

  if(file->optionalImage == OPTIONAL_IMAGE_64)
  {
    fseek(in, 4, SEEK_CUR);
    file->ImageBase = get64_le(in);
    fclose(in);
    return;
  }

  if(fseek(in, 8, SEEK_CUR) != -1)
  {
    file->ImageBase = get32_le(in);
  }

  fclose(in);
}