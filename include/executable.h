/*
 * tracker is an hybrid trustworthy disassembler that tries to limit the number
 * of false positive paths discovered.
 *
 *  Written and maintained by Emmanuel Fleury <emmanuel.fleury@u-bordeaux.fr>
 *
 * Copyright 2019 University of Bordeaux, CNRS (UMR 5800), France.
 * All rights reserved.
 *
 * This software is released under a 3-clause BSD license (see COPYING file).
 */

#ifndef _EXECUTABLE_H
#define _EXECUTABLE_H

#include <stdint.h>
#include <stdio.h>

/* Executable type */
typedef struct _executable_t executable_t;

/* Platform architecture arch_t type */
typedef enum { unknown_arch = 0, x86_32_arch = 1, x86_64_arch = 2 } arch_t;

/* Create and initialize a new executable_t */
executable_t *exec_new (char *execfilename);

/* Free the given executable */
void exec_delete (executable_t *exec);

/* Get executable architecture */
arch_t exec_arch (executable_t *exec);

/* Print the current architecture of the executable file */
void exec_print_arch (executable_t *exec, FILE *fd);

/* Iterator on executable sections, return NULL after last item and cycle */
char *executable_section_next (executable_t *exec);

/* Get the section that contains the given address */
char *executable_get_section_by_addr (executable_t *exec, uintptr_t addr);

/* Get symbol by address, return NULL if no symbol is matching */
char *executable_get_symbol_by_addr (executable_t *exec, uintptr_t addr);

#endif /* _EXECUTABLE_H */
