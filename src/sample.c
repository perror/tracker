#include <stdio.h>
#include <stdlib.h>

#include <executable.h>

int
main (void)
{
  char *execfilename = "/bin/ls";
  executable_t *exec = exec_new (execfilename);

  printf("Executable: %s\n", execfilename);
  printf ("Arch: %d\n", exec_arch(exec));


  exec_delete(exec);

  return EXIT_SUCCESS;
}
