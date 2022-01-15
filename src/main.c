// main.c:
//    main block of PErser program

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
      read_pe(in, &dosHeader);
      print_info(&dosHeader);
      fclose(in);
    }
  }

  if(in != NULL) fclose(in);

  return 0;
}