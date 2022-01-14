// main.c:
//    main block of PErser program

#include "pe_header.h"

int main(int argc, char* argv[])
{

  if(argc < 2){
    printf("please supply at least One valid PE file\n");
    exit(1);
  }

  dos_header dosHeader;
  pe_header peHeader;
  optional_header optionalHeader;

  dosHeader.pe = &peHeader;
  peHeader.optionalHeader = &optionalHeader;

  for(int i = 0; i < argc; i++){
    read_pe(argv[i], &dosHeader);
    print_info(argv[i], &dosHeader);
  }

  return 0;
}