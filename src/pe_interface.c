// pe-interface.c: 
//    contains functions that deals with PE structures
//    reading PE values and saving them in a struct.
#include "pe_header.h"

// 
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
  printf("OptionalHeader size:   0x%x\n",
         file->optionalHeaderSize);
  
  printf("Characteristics:       ");
  if( file->characteristics & (IMAGE_FILE_DLL) ){
    printf("DLL \n");
  } else if(file->characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE) ){
    printf("EXE \n");
  }

  switch (file->optionalImage)
  {
  case 0x10b:
    printf("Optional Image header: 0x%x PE (32 bit) \n",
           file->optionalImage);
    break;
  case 0x20b:
    printf("Optional Image header: 0x%x PE+ (64 bit) \n",
           file->optionalImage);
    break;

  default:
    break;
  }

}

void read_pe(char *filename, pe_file *file)
{
  FILE *in;
  int val = 0;
  in = fopen(filename, "rb");
  if(in == NULL)
  {
    exit(-1);
  }
  // reading e_lfnew value (offset to PE)
  if(fseek(in, 0x3c, SEEK_SET) != -1)
  {
    val = fgetc(in) | (fgetc(in)<<8) | (fgetc(in)<<16) | (fgetc(in)<<24);
    file->PE_offset = val;
  }

  // PE's signature, Machine and number of sections
  if(fseek(in, file->PE_offset, SEEK_SET) != -1)
  {
    file->sig[0] = fgetc(in);
    file->sig[1] = fgetc(in);
    file->sig[2] = fgetc(in);
    file->sig[3] = fgetc(in);
    //file.sig[4] = '\0';

    val = fgetc(in) | (fgetc(in)<<8);

    file->machine = val;
    file->sections = fgetc(in) | (fgetc(in)<<8);
  }

// SizeOfOptionalHeader and Characteristics
  if(fseek(in, file->PE_offset+20, SEEK_SET) != -1)
  {
    val = fgetc(in) | (fgetc(in)<<8);
    file->optionalHeaderSize = val;

    val = fgetc(in) | (fgetc(in)<<8);
    file->characteristics = val;

    val = fgetc(in) | (fgetc(in)<<8);
    file->optionalImage = val;
  }

  fclose(in);
}