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
		    const uint8_t * const opcodes);

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
bool hashtable_insert (hashtable_t *const ht, instr_t *const instr);

/* Look-up if current instruction is already in the hashtable */
bool hashtable_lookup (hashtable_t *const ht, instr_t *const instr);

/* Count the number of entries in the hashtable */
size_t hashtable_entries (hashtable_t *const ht);

/* Count the number of collisions in the hashtable */
size_t hashtable_collisions (const hashtable_t *ht);

/* Count the number of non empty buckets in the hashtable */
size_t hashtable_filled_buckets (const hashtable_t * const ht);

/* ***** Execution trace ***** */

typedef struct _trace_t trace_t;

/* Create a new trace_t structure with a unique instruction */
trace_t *trace_new (void);

/* Free all the trace tr */
void trace_delete (trace_t *tr);

/* Append the instruction instr to the tail of the trace,
 * returns 0 if everything went well and -1 otherwise */
int trace_append (trace_t * const tr, instr_t * const instr);

/* Returns the i-th element of the trace (starts at 1) and NULL on error */
instr_t *trace_get (trace_t * const tr, const size_t index);

/* Returns trace length */
size_t trace_length (trace_t * const tr);

/* Returns 0 if the traces matches or the index > 0 from which it differs */
size_t trace_compare (trace_t * const t1, trace_t * const t2);

/* ***** Execution control-flow graph ***** */

typedef struct _cfg_t cfg_t;
typedef enum { single = 0, branch = 1, dynjump = 2 } node_t;

cfg_t *cfg_new (instr_t *instr, node_t node_type);
cfg_t *cfg_insert (cfg_t *cfg, instr_t *instr, node_t node_type);
void cfg_delete (cfg_t *cfg);

#endif /* _TRACES_H */
