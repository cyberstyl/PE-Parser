/*
 *
 *
*/

#include "pe-header.h"

int main(int argc, char* argv[])
{
  pe_file file;
  read_pe(argv[1], &file);
  print_info(&file);

  return 0;
}