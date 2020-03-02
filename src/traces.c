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

#include "traces.h"

#include <errno.h>
#include <string.h>

/* **********[ Instruction Data-structure ]********** */

typedef enum { INSTR, BRANCH, CALL, JMP } instr_type_t;

struct _instr_t
{
  uintptr_t address; /* Address where lies the instruction */
  instr_type_t type; /* Instruction type */
  uint8_t size;	     /* Opcode size */
  uint8_t opcodes[]; /* Instruction opcode */
};

instr_t *
instr_new (const uintptr_t addr, const uint8_t size, const uint8_t *const opcodes)
{
  /* Check size != 0 and opcodes != NULL */
  if (size == 0 || opcodes == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  instr_t *instr = malloc (sizeof (instr_t) + size * sizeof (uint8_t));
  if (instr == NULL)
    return NULL;

  instr->address = addr;
  instr->size = size;
  memcpy (instr->opcodes, opcodes, size);

  return instr;
}

void
instr_delete (instr_t *instr)
{
  free (instr);
}

uintptr_t
instr_addr (instr_t *const instr)
{
  return instr->address;
}

size_t
instr_size (instr_t *const instr)
{
  return instr->size;
}

uint8_t *
instr_opcodes (instr_t *const instr)
{
  return instr->opcodes;
}

/* **********[ Hashtable Data-structure ]********** */

struct _hashtable_t
{
  size_t size;	       /* Hashtable size */
  size_t collisions;   /* Number of collisions encountered */
  size_t entries;      /* Number of entries registered */
  instr_t **buckets[]; /* Hachtable buckets */
};

/* Compression function for Merkle-Damgard construction */
#define mix(h)                                                                 \
  ({                                                                           \
    (h) ^= (h) >> 23ULL;                                                       \
    (h) *= 0x2127598bf4325c37ULL;                                              \
    (h) ^= (h) >> 47ULL;                                                       \
  })

hash_t
fasthash64 (const uint8_t *buf, size_t len, uint64_t seed)
{
  const uint64_t m = 0x880355f21e6d1965ULL;
  const uint64_t *pos = (const uint64_t *) buf;
  const uint64_t *end = pos + (len / 8);
  const uint8_t *pos2;

  uint64_t h = seed ^ (len * m);
  uint64_t v;

  while (pos != end)
    {
      v = *pos++;
      h ^= mix (v);
      h *= m;
    }

  pos2 = (const uint8_t *) pos;
  v = 0;

  switch (len & 7)
    {
    case 7:
      v ^= (uint64_t) pos2[6] << 48ULL;
      /* FALLTHROUGH */
    case 6:
      v ^= (uint64_t) pos2[5] << 40ULL;
      /* FALLTHROUGH */
    case 5:
      v ^= (uint64_t) pos2[4] << 32ULL;
      /* FALLTHROUGH */
    case 4:
      v ^= (uint64_t) pos2[3] << 24ULL;
      /* FALLTHROUGH */
    case 3:
      v ^= (uint64_t) pos2[2] << 16ULL;
      /* FALLTHROUGH */
    case 2:
      v ^= (uint64_t) pos2[1] << 8ULL;
      /* FALLTHROUGH */
    case 1:
      v ^= (uint64_t) pos2[0];
      h ^= mix (v);
      h *= m;
    }

  return mix (h);
}

hash_t
hash_instr (const instr_t *instr)
{
  return fasthash64 (instr->opcodes, instr->size, instr->address);
}

hashtable_t *
hashtable_new (const size_t size)
{
  if (size == 0)
    {
      errno = EINVAL;
      return NULL;
    }

  hashtable_t *ht = malloc (sizeof (hashtable_t) + size * sizeof (instr_t *));
  if (ht == NULL)
    return NULL;

  /* Initialize to zero */
  *ht = (hashtable_t){0};
  ht->size = size;
  ht->collisions = 0;
  ht->entries = 0;
  memset (ht->buckets, 0, size * sizeof (instr_t *));

  return ht;
}

void
hashtable_delete (hashtable_t *ht)
{
  for (size_t i = 0; i < ht->size; i++)
    {
      if (ht->buckets[i])
	{
	  size_t j = 0;
	  while (ht->buckets[i][j])
	    {
	      instr_delete (ht->buckets[i][j]);
	      j++;
	    }
	}
      free (ht->buckets[i]);
    }

  free (ht);
}

bool
hashtable_insert (hashtable_t *const ht, instr_t *const instr)
{
  if (ht == NULL || instr == NULL)
    {
      errno = EINVAL;
      return false;
    }

  size_t index = hash_instr (instr) % ht->size;

  /* Bucket is empty */
  if (ht->buckets[index] == NULL)
    {
      ht->buckets[index] = calloc (2, sizeof (instr_t *));
      if (ht->buckets[index] == NULL)
	return false;

      ht->buckets[index][0] = instr;
      ht->entries++;
      return true;
    }

  /* Bucket isn't NULL, scanning all entries to see if instr is already here */
  size_t k = 0;
  instr_t **bucket_instr = ht->buckets[index];
  while (bucket_instr[k] != NULL)
    {
      if (bucket_instr[k]->address == instr->address &&
	  bucket_instr[k]->size == instr->size &&
	  !strncmp ((const char *) bucket_instr[k]->opcodes,
		    (const char *) instr->opcodes, instr->size))
	return false;
      k++;
    }

  instr_t **new_bucket = calloc (k + 2, sizeof (instr_t *));
  if (new_bucket == NULL)
    return false;

  ht->collisions++;
  ht->entries++;
  memcpy (new_bucket, ht->buckets[index], k * sizeof (instr_t *));
  new_bucket[k] = instr;
  free (ht->buckets[index]);
  ht->buckets[index] = new_bucket;

  return true;
}

bool
hashtable_lookup (hashtable_t *const ht, instr_t *const instr)
{
  if (ht == NULL || instr == NULL)
    {
      errno = EINVAL;
      return false;
    }

  size_t index = hash_instr (instr) % ht->size;

  /* Bucket is empty */
  if (ht->buckets[index] == NULL)
    return false;

  /* Bucket is not empty, scanning all entries to see if instr is here */
  size_t k = 0;
  instr_t **bucket_instr = ht->buckets[index];
  while (bucket_instr[k] != NULL)
    {
      if (bucket_instr[k]->address == instr->address &&
	  bucket_instr[k]->size == instr->size &&
	  !strncmp ((const char *) bucket_instr[k]->opcodes,
		    (const char *) instr->opcodes, instr->size))
	return true;
      k++;
    }

  return false;
}

size_t
hashtable_entries (hashtable_t *const ht)
{
  return ht->entries;
}

size_t
hashtable_collisions (const hashtable_t *const ht)
{
  return ht->collisions;
}

size_t
hashtable_filled_buckets (const hashtable_t * const ht)
{
  size_t count = 0;
  for (size_t index = 0; index < ht->size; index++)
    count += (ht->buckets[index] != NULL);

  return count;
}

/* **********[ Trace Data-structure ]********** */

typedef struct tnode_t
{
  instr_t *instr;
  struct tnode_t *next;
} tnode_t;

struct _trace_t
{
  tnode_t *head;
  tnode_t *tail;
};

trace_t *
trace_new (void)
{
  trace_t *tr = malloc (sizeof (trace_t));
  if (tr == NULL)
    return NULL;

  /* Set the trace structure */
  tr->head = NULL;
  tr->tail = NULL;

  return tr;
}

void
trace_delete (trace_t *tr)
{
  if (tr == NULL || tr->head == NULL || tr->tail == NULL)
    return;

  tnode_t *node = tr->head;
  while (node->next)
    {
      tnode_t *next_node = node->next;
      free (node);
      node = next_node;
    }
  free (tr);
}

int
trace_append (trace_t * const tr, instr_t * const instr)
{
  if (tr == NULL || instr == NULL)
    {
      errno = EINVAL;
      return -1;
    }

  /* Create the new node */
  tnode_t *node = malloc (sizeof (tnode_t));
  if (node == NULL)
    return -1;

  node->instr = instr;
  node-> next = NULL;

  /* No node are present yet */
  if (tr->head == NULL)
    {
      tr->head = node;
      tr->tail = node;

      goto end;
    }

  /* Nominal case */
  tr->tail->next = node;
  tr->tail = node;

 end:
  return 0;
}

instr_t *
trace_get (trace_t * const tr, const size_t index)
{
  if (tr == NULL || index < 1)
    {
      errno = EINVAL;
      return NULL;
    }

  size_t k = 0;
  tnode_t *current = tr->head;

  while (k < index - 1)
    {
      k++;
      current = current->next;
      if (current == NULL)
	return NULL;
    }
  return current->instr;
}

size_t
trace_length (trace_t * const tr)
{
  if (tr == NULL)
    {
      errno = EINVAL;
      return 0;
    }
  size_t length = 0;
  tnode_t *node = tr->head;
  while (node != NULL)
    {
      node = node->next;
      length++;
    }
  return length;
}

size_t
trace_compare (trace_t * const t1, trace_t * const t2)
{
  size_t count = 1;

  if (t1 == NULL || t2 == NULL)
    {
      errno = EINVAL;
      return 1;
    }

  /* Special cases when one of the trace is empty */
  if (t1->head == NULL || t2->head == NULL)
    return count;

  tnode_t * n1 = t1->head, *n2 = t2->head;
  while (n1->instr == n2->instr)
    {
      n1 = n1->next;
      n2 = n2->next;
      count++;

      if (n1 == NULL && n2 == NULL)
	return 0;

      if (n1 == NULL || n2 == NULL)
	break;
    }

  return count;
}
