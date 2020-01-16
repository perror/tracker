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

#ifndef _TRACE_H
#define _TRACE_H

#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#define DEFAULT_HASHTABLE_SIZE 65536 /* 2^16 */

/* ***** Handling assembly instructions ***** */

typedef struct _instr_t instr_t;

/* Return a new instr_t struct, NULL otherwise (and set errno) */
instr_t *instr_new (const uintptr_t addr,
		    const uint8_t size,
		    const uint8_t *opcodes);

/* Delete the assembly instruction from memory */
void instr_delete (instr_t *instr);

/* Get the address of the instruction */
uintptr_t instr_get_addr (instr_t * const instr);

/* Get the size (in bytes) of the instruction */
size_t instr_get_size (instr_t * const instr);

/* Get a pointer to the opcodes of the instruction */
uint8_t * instr_get_opcodes (instr_t * const instr);

/* ***** Hashtables to store instructions ***** */

typedef uint64_t hash_t;
typedef struct _hashtable_t hashtable_t;

/* Return an hash index for the instruction */
uint64_t hash_instr (const instr_t *instr);

/* Initialize a new hashtable of given size, returns NULL is size == 0 */
hashtable_t *hashtable_new (const size_t size);

/* Free the given hashtable */
void hashtable_delete (hashtable_t *ht);

/* Insert the instruction in the hashtable */
bool hashtable_insert (hashtable_t * ht, instr_t * instr);

/* Look-up if current instruction is already in the hashtable */
bool hashtable_lookup (hashtable_t *ht, instr_t *instr);

/* Count the number of entries in the hashtable */
size_t hashtable_entries (hashtable_t *ht);

/* Count the number of collisions in the hashtable */
size_t hashtable_collisions (hashtable_t *ht);

/* ***** Linked list to store an execution trace ***** */

typedef struct _trace_t trace_t;

/* Creates a trace and initialize the first element with hash_index
 * Returns a pointer to the created trace, or NULL if an error occured */
trace_t *trace_new (uint64_t hash_index);

/* Insert an element initialized with hash_index and insert it after t
 * Returns a pointer to the created element or NULL if an error occured */
trace_t *trace_insert (trace_t *t, uint64_t hash_value);

/* Free every element in the trace t */
void trace_delete (trace_t *t);

/* Returns the first element where t1 and t2 differs, NULL otherwise */
trace_t *trace_compare (trace_t *t1, trace_t *t2);

#endif /* _TRACE_H */
