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

#ifndef _TRACES_H
#define _TRACES_H

#include <stdbool.h>
#include <stdlib.h>

#include <inttypes.h>

#define DEFAULT_HASHTABLE_SIZE 1ULL << 16

/* ***** Assembly instructions ***** */

typedef struct _instr_t instr_t;

/* Return a new instr_t struct, NULL otherwise (and set errno) */
instr_t *instr_new (const uintptr_t addr, const uint8_t size,
		    const uint8_t *opcodes);

/* Delete the assembly instruction from memory */
void instr_delete (instr_t *instr);

/* Get the address of the instruction */
uintptr_t instr_addr (instr_t *const instr);

/* Get the size (in bytes) of the instruction */
size_t instr_size (instr_t *const instr);

/* Get a pointer to the opcodes of the instruction */
uint8_t *instr_opcodes (instr_t *const instr);

/* ***** Instructions' hashtables ***** */

typedef uint64_t hash_t;
typedef struct _hashtable_t hashtable_t;

/* Return an hash index for the instruction */
uint64_t hash_instr (const instr_t *instr);

/* Initialize a new hashtable of given size, returns NULL is size == 0 */
hashtable_t *hashtable_new (const size_t size);

/* Free the given hashtable */
void hashtable_delete (hashtable_t *ht);

/* Insert the instruction in the hashtable, returns true if insertion is
   successful, false if instruction was already here or a problem occured */
bool hashtable_insert (hashtable_t *ht, instr_t *instr);

/* Look-up if current instruction is already in the hashtable */
bool hashtable_lookup (hashtable_t *ht, instr_t *instr);

/* Count the number of entries in the hashtable */
size_t hashtable_entries (hashtable_t *ht);

/* Count the number of collisions in the hashtable */
size_t hashtable_collisions (hashtable_t *ht);

/* Count the number of non empty buckets in the hashtable */
size_t hashtable_filled_buckets (hashtable_t *ht);

/* ***** Execution trace ***** */

typedef struct _trace_t trace_t;

/* Append an instr on the top of the trace t (or create a new trace if
 * t == NULL) and returns a pointer to the new trace top or NULL otherwise */
trace_t *trace_insert (trace_t *t, instr_t *instr);

/* Free every element in the trace t */
void trace_delete (trace_t *t);

/* Returns the first element where t1 and t2 differs, NULL otherwise */
trace_t *trace_compare (trace_t *t1, trace_t *t2);

/* ***** Execution control-flow graph ***** */

typedef struct _cfg_t cfg_t;
typedef enum { single = 0, branch = 1, dynjump = 2 } node_t;

cfg_t *cfg_new (instr_t *instr, node_t node_type);
cfg_t *cfg_insert (cfg_t *cfg, instr_t *instr, node_t node_type);
void cfg_delete (cfg_t *cfg);

#endif /* _TRACES_H */
