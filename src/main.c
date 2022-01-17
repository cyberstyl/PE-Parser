// main.c:
//    main block of PErser program

#include "headers.h"
#include "pe_header.h"

int main(int argc, char* argv[])
{
  FILE *in;
  dos_header_t dosHeader;

  if(argc < 2){
    printf("please supply at least One valid PE file\n");
    exit(1);
  }



  if (argc >= 2)
  {

    for(int i = 1; i < argc; i++)
    {
      in = fopen(argv[i], "rb");
      if(in == NULL)
      {
        printf("Can't open '%s' file, exiting\n", argv[i]);
        continue;
      }      

      printf("showing file: %s \n\n", argv[i]);
      read_dos(in, &dosHeader);
      if( fseek(in, dosHeader.e_lfanew, SEEK_SET) == -1)
      {  
        printf("Error during file reading.\n");
        exit(-1);
      }

      read_pe(in, &dosHeader);
      read_dataDir(in, &dosHeader);
      read_sections(in, &dosHeader);
      read_exportDir(in, &dosHeader);
      print_info(&dosHeader);
      
      
      cleanup(&dosHeader);
      fclose(in);
    }
  }  

  return 0;
}