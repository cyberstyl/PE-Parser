// main.c:
//    main block of PErser program

#include "pe_header.h"

int main(int argc, char* argv[])
{

  dos_header dosHeader;
  pe_header peHeader;
  optional_header optionalHeader;

  dosHeader.pe = &peHeader;
  peHeader.optionalHeader = &optionalHeader;

  read_pe(argv[1], &dosHeader);
  print_info(&dosHeader);

  return 0;
}