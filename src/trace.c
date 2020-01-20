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

#include <trace.h>

#include <errno.h>
#include <string.h>

struct _instr_t
{
  uintptr_t address; /* Address where lies the instruction */
  // uintptr_t *next; /* List of addresses of the next instructions */
  // uint8_t type;    /* Instr type: 0 = instr, 1 = branch, 2 = call, 3 = jmp */
  uint8_t size;       /* Opcode size */
  uint8_t opcodes[];  /* Instruction opcode */
};

instr_t *
instr_new (const uintptr_t addr, const uint8_t size, const uint8_t *opcodes)
{
  /* Check size != 0 and opcodes != NULL */
  if (size == 0 || opcodes == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  instr_t *instr = malloc (sizeof (instr_t) + size * sizeof (uint8_t));
  if (!instr)
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
instr_get_addr (instr_t * const instr)
{
  return instr->address;
}

size_t
instr_get_size (instr_t * const instr)
{
  return instr->size;
}

uint8_t *
instr_get_opcodes (instr_t * const instr)
{
  return instr->opcodes;
}

/* Hashtable implementation */

struct _hashtable_t
{
  size_t size;          /* Hashtable size */
  size_t collisions;    /* Number of collisions encountered */
  size_t entries;       /* Number of entries registered */
  instr_t ** buckets[]; /* Hachtable buckets */
};

/* Compression function for Merkle-Damgard construction */
#define mix(h) ({				\
		(h) ^= (h) >> 23;		\
		(h) *= 0x2127598bf4325c37ULL;	\
		(h) ^= (h) >> 47; })

hash_t
fasthash64 (const uint8_t *buf, size_t len, uint64_t seed)
{
  const uint64_t    m = 0x880355f21e6d1965ULL;
  const uint64_t *pos = (const uint64_t *) buf;
  const uint64_t *end = pos + (len / 8);
  const uint8_t  *pos2;

  uint64_t h = seed ^ (len * m);
  uint64_t v;

  while (pos != end) {
    v  = *pos++;
    h ^= mix(v);
    h *= m;
  }

  pos2 = (const uint8_t *) pos;
  v = 0;

  switch (len & 7) {
  case 7: v ^= (uint64_t) pos2[6] << 48;
    /* FALLTHROUGH */
  case 6: v ^= (uint64_t) pos2[5] << 40;
    /* FALLTHROUGH */
  case 5: v ^= (uint64_t) pos2[4] << 32;
    /* FALLTHROUGH */
  case 4: v ^= (uint64_t) pos2[3] << 24;
    /* FALLTHROUGH */
  case 3: v ^= (uint64_t) pos2[2] << 16;
    /* FALLTHROUGH */
  case 2: v ^= (uint64_t) pos2[1] << 8;
    /* FALLTHROUGH */
  case 1: v ^= (uint64_t) pos2[0];
    h ^= mix(v);
    h *= m;
  }

  return mix(h);
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
  if (!ht)
    return NULL;

  /* Initialize to zero */
  *ht = (hashtable_t) { 0 };
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

#include <stdio.h>

bool
hashtable_insert (hashtable_t * ht, instr_t * instr)
{
  if (ht == NULL || instr == NULL)
    {
      errno = EINVAL;
      return false;
    }

  size_t index = hash_instr(instr) % ht->size;

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
  while (ht->buckets[index][k] != NULL)
    if (ht->buckets[index][k++]->address == instr->address)
      return false; /* No error but we need to delete the redundant one */

  instr_t **new_bucket = calloc (k + 2, sizeof (instr_t *));
  if (!new_bucket)
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
hashtable_lookup (hashtable_t *ht, instr_t *instr)
{
  if (!ht)
    return false;

  size_t index = hash_instr (instr) % ht->size;

  /* Bucket is empty */
  if (ht->buckets[index] == NULL)
    return false;

  /* Bucket is not empty, scanning all entries to see if instr is here */
  size_t k = 0;
  while (ht->buckets[index][k] != NULL)
    if (ht->buckets[index][k++]->address == instr->address)
      return true;

  return false;
}

size_t
hashtable_entries (hashtable_t *ht)
{
  return ht->entries;
}

size_t
hashtable_collisions (hashtable_t *ht)
{
  return ht->collisions;
}

struct _trace_t
{
  hash_t h;    /* Index for the hash value of the instruction */
  trace_t *next; /* Pointer to the next value in the list */
};

trace_t *
trace_new (hash_t hash_index)
{
  trace_t *t = malloc (sizeof (trace_t));
  if (!t)
    return NULL;

  t->h = hash_index;
  t->next = NULL;

  return t;
}

trace_t *
trace_insert (trace_t *t, hash_t hash_index)
{
  if (!t)
    return NULL;

  trace_t *new = trace_new (hash_index);
  if (!new)
    return NULL;

  if (t->next)
    new->next = t->next;
  t->next = new;

  return new;
}

void
trace_delete (trace_t *t)
{
  if (!t)
    return;

  trace_t *tmp = t;
  while (tmp->next)
    {
      tmp = tmp->next;
      free(t);
      t = tmp;
    }
  free(t);

  return;
}

trace_t *
trace_compare (trace_t *t1, trace_t *t2)
{
  trace_t *tmp1 = t1, *tmp2 = t2;

  while (tmp1->h == tmp2->h)
    {
      tmp1 = tmp1->next;
      tmp2 = tmp2->next;

      if (!tmp1)
	return tmp2;

      if (!tmp2)
	return NULL;
    }

  return tmp2;
}
