/*
 * tracker is an analyzer for binary executable files
 *
 *  Written and maintained by Emmanuel Fleury <emmanuel.fleury@u-bordeaux.fr>
 *
 * Copyright 2019-2020 University of Bordeaux, CNRS (UMR 5800), France.
 * All rights reserved.
 *
 * This software is released under a 3-clause BSD license (see COPYING file).
 */

#include "executables.h"

#include <stdlib.h>

#include <elf.h>
#include <err.h>
#include <string.h>

#include <sys/stat.h>

struct _executable_t
{
  arch_t arch;
  union
  {
    Elf32_Ehdr elf32;
    Elf64_Ehdr elf64;
  } header;
};

executable_t *
executable_new (char *execfilename)
{
  struct stat exec_stats;
  if (stat (execfilename, &exec_stats) == -1)
    err (EXIT_FAILURE, "error: '%s'", execfilename);

  if (!S_ISREG (exec_stats.st_mode) || !(exec_stats.st_mode & S_IXUSR))
    errx (EXIT_FAILURE, "error: '%s' is not an executable file", execfilename);

  /* Check if given file is an executable and discover its architecture */
  FILE *execfile = fopen (execfilename, "rb");
  if (execfile == NULL)
    err (EXIT_FAILURE, "error: '%s'", execfilename);

  /* Open file */
  char buf[4] = {0};
  if (fread (&buf, 4, 1, execfile) != 1)
    errx (EXIT_FAILURE, "error: cannot read '%s'", execfilename);

  /* Check ELF magic number (first 4 bytes: 0x7f "ELF") */
  if (buf[0] != 0x7f || strncmp (&(buf[1]), "ELF", 3) != 0)
    errx (EXIT_FAILURE, "error: '%s' is not an ELF binary", execfilename);

  /* Extract executable architecture (byte at 0x12) */
  fseek (execfile, 0x12, SEEK_SET);
  if (fread (&buf, 1, 1, execfile) != 1)
    errx (EXIT_FAILURE, "error: cannot read '%s'", execfilename);
  rewind (execfile);

  executable_t *exec = malloc (sizeof (executable_t));
  if (exec == NULL)
    return NULL;

  switch (buf[0])
    {
    case 0x03:
      exec->arch = x86_32_arch;
      fread (&(exec->header.elf32), 1, sizeof (Elf32_Ehdr), execfile);
      break;

    case 0x3e:
      exec->arch = x86_64_arch;
      fread (&(exec->header.elf64), 1, sizeof (Elf64_Ehdr), execfile);
      break;

    default:
      errx (EXIT_FAILURE, "error: '%s' unsupported architecture", execfilename);
    }

  /* Closing file after verifications */
  fclose (execfile);

  return exec;
}

void
executable_delete (executable_t *exec)
{
  free (exec);
}

arch_t
executable_arch (executable_t *exec)
{
  if (exec == NULL)
    return unknown_arch;

  return exec->arch;
};

void
executable_print_arch (executable_t *exec, FILE *fd)
{
  const char *arch2str[3] = {"Unknown architecture", "x86-32", "x86-64"};

  if (exec == NULL)
    fputs (arch2str[unknown_arch], fd);

  fputs (arch2str[exec->arch], fd);
}

char *
executable_section_next (executable_t *exec)
{
  return NULL;
}

char *
executable_get_section_by_addr (executable_t *exec, uintptr_t addr)
{
  return NULL;
}

char *
executable_get_symbol_by_addr (executable_t *exec, uintptr_t addr)
{
  return NULL;
}
