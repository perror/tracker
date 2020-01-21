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
#include <stdio.h>

struct _instr_t
{
  uintptr_t address; /* Address where lies the instruction */
  // uintptr_t *next; /* List of addresses of the next instructions */
  uint8_t type;    /* Instr type: 0 = instr, 1 = branch, 2 = call, 3 = jmp */
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

	if ((opcodes[0] >= 0x70 && opcodes[0] <= 0x7F)
	|| (opcodes[0] == 0x0F && opcodes[1] >= 0x80 && opcodes[1] <= 0x8F))
		instr->type = 1;
	else if (opcodes[0] == 0xE8 || opcodes[0] == 0x9A
		|| (opcodes[0] == 0xFF && (size == 2 || size == 3)))
		instr->type = 2;
	else if ((opcodes[0] >= 0xE9 && opcodes[0] <= 0xEB)
	|| (opcodes[0] == 0xFF && (size == 4 || size == 5)))
		instr->type = 3;
	else
		instr->type = 0;
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
  cfg_t ** buckets[]; /* Hachtable buckets */
};


struct _cfg_t
{
	instr_t *instruction;
	uint16_t nb_in;
	uint16_t nb_out;
	cfg_t **successor;
};

/* Compression function for Merkle-Damgard construction */
#define mix(h) ({				\
		(h) ^= (h) >> 23;		\
		(h) *= 0x2127598bf4325c37ULL;	\
		(h) ^= (h) >> 47; })

uint64_t
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

uint64_t
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

  hashtable_t *ht = malloc (sizeof (hashtable_t) + size * sizeof (cfg_t *));
  if (!ht)
    return NULL;

  /* Initialize to zero */
  *ht = (hashtable_t) { 0 };
  ht->size = size;
  ht->collisions = 0;
  ht->entries = 0;
  memset (ht->buckets, 0, size * sizeof (cfg_t *));

  return ht;
}

void
hashtable_delete (hashtable_t *ht)
{
  for (size_t i = 0; i < ht->size; i++)
		{
			size_t j = 0;
			if (ht->buckets[i])
				{
					while (ht->buckets[i][j] != NULL)
						{
							cfg_delete (ht->buckets[i][j]);
							j++;
						}
					free (ht->buckets[i]);
				}
		}
  free (ht);
}

#include <stdio.h>

bool
hashtable_insert (hashtable_t * ht, cfg_t *CFG)
{
  if (ht == NULL || CFG->instruction == NULL)
    {
      errno = EINVAL;
      return false;
    }

  size_t index = hash_instr (CFG->instruction) % ht->size;

  /* Bucket is empty */
  if (ht->buckets[index] == NULL)
    {
      ht->buckets[index] = calloc (2, sizeof (cfg_t *));
      if (ht->buckets[index] == NULL)
				return false;
      ht->buckets[index][0] = CFG;
      ht->entries++;
      return true;
    }

  /* Bucket isn't NULL, scanning all entries to see if instr is already here */
  size_t k = 0;
  while (ht->buckets[index][k] != NULL)
	{
    if (ht->buckets[index][k]->instruction->address == CFG->instruction->address)
			return true; /* No error but we need to delete the redundant one */
		k++;
	}
  cfg_t **new_bucket = calloc (k + 2, sizeof (cfg_t *));
  if (!new_bucket)
		return false;

  ht->collisions++;
  ht->entries++;
  memcpy (new_bucket, ht->buckets[index], k * sizeof (cfg_t *));
  new_bucket[k] = CFG;
  free (ht->buckets[index]);
  ht->buckets[index] = new_bucket;

  return true;
}

cfg_t *
hashtable_lookup (hashtable_t *ht, instr_t *instr)
{
  if (!ht)
    return NULL;

  size_t index = hash_instr (instr) % ht->size;

  /* Bucket is empty */
  if (ht->buckets[index] == NULL)
    return NULL;

  /* Bucket is not empty, scanning all entries to see if instr is here */
  size_t k = 0;
  while (ht->buckets[index][k] != NULL)
		{
	    if (ht->buckets[index][k]->instruction->address == instr->address)
				return ht->buckets[index][k];
			k++;
		}
  return NULL;
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

/*****************************************/


struct _trace_t
{
	instr_t *instruction; /* Index for the hash value of the instruction */
	trace_t *next; /* Pointer to the next value in the list */
};

trace_t *
trace_new (instr_t *ins)
{
	trace_t *t = malloc (sizeof (trace_t));
	if (!t)
		return NULL;
	t->instruction = ins;
	t->next = NULL;
	return t;
}

trace_t *
trace_insert (trace_t *t, instr_t *ins)
{
	if (!t)
		return NULL;
	trace_t *new = trace_new (ins);
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
	trace_t *tmp1 = t1;
	trace_t *tmp2 = t2;
	while (tmp1->instruction->address == tmp2->instruction->address)
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

/********************************************************************/


cfg_t *
cfg_new (instr_t *ins)
{
	cfg_t *CFG = malloc (sizeof (cfg_t));
	if (!CFG)
		return NULL;
	CFG->instruction =  ins;
	CFG->nb_in = 0;
	CFG->nb_out = 0;
	switch (ins->type)
	{
		case 0:
			CFG->successor = calloc (1, sizeof (cfg_t *));
			if (!CFG->successor)
				{
					cfg_delete (CFG);
					return NULL;
				}
			CFG->successor[0] = calloc (1, sizeof (cfg_t));
			if (!CFG->successor[0])
			{
				cfg_delete (CFG);
				return NULL;
			}
			CFG->successor[0] = NULL;
			break;
		case 1:
			CFG->successor = calloc (2, sizeof (cfg_t *));
			if (!CFG->successor)
			{
				cfg_delete (CFG);
				return NULL;
			}
			for (int i = 0; i < 2; i++)
				{
					CFG->successor[i] = calloc (1, sizeof (cfg_t));
					if (!CFG->successor[i])
					{
						cfg_delete (CFG);
						return NULL;
					}
				}
			CFG->successor[0] = NULL;
			break;
		case 2:
			CFG->successor = calloc (1, sizeof (cfg_t *));
			if (!CFG->successor)
			{
				cfg_delete (CFG);
				return NULL;
			}
			CFG->successor[0] = calloc (1, sizeof (cfg_t));
			if (!CFG->successor[0])
			{
				cfg_delete (CFG);
				return NULL;
			}
			CFG->successor[0] = NULL;
			break;
			if (!CFG->successor)
			{
				cfg_delete (CFG);
				return NULL;
			}
			break;
		case 3:
			CFG->successor = calloc (2, sizeof (cfg_t *));
			if (!CFG->successor)
			{
				cfg_delete (CFG);
				return NULL;
			}
			for (int i = 0; i < 2; i++)
				{
					CFG->successor[i] = calloc (1, sizeof (cfg_t));
					if (!CFG->successor[i])
					{
						cfg_delete (CFG);
						return NULL;
					}
				}
			CFG->successor[0] = NULL;
			break;
	}
	return CFG;
}

static bool
is_power_2 (uint16_t n)
{
	if (n == 0)
		return false;
	while (n % 2 == 0)
		{
			if (n == 2)
				return true;
			n = n / 2;
		}
	return false;
}

cfg_t *
aux_cfg_insert (cfg_t *CFG, cfg_t *new)
{
	if (!new)
		return NULL;
	if (!CFG->successor[0])
		{
			CFG->successor[0] = new;
			CFG->nb_out++;
			new->nb_in++;
		}
	else if (CFG->instruction->type == 1 || CFG->instruction->type == 3)
		{
			if (CFG->instruction->type == 1)
				{
					if (!CFG->successor[1])
						return NULL;
					else
						{
							CFG->successor[1] = new;
							CFG->nb_out++;
							new->nb_in++;
						}
				}
			if (CFG->instruction->type == 3)
				{
					if (is_power_2 (CFG->nb_out))
						CFG->successor = realloc (CFG->successor, 2 * CFG->nb_out * sizeof (cfg_t *));
					if (!CFG->successor)
					{
						cfg_delete (CFG);
						return NULL;
					}
					CFG->successor[CFG->nb_out] = new;
					CFG->nb_out++;
					new->nb_in++;
				}
			}
		return new;
}

cfg_t *
cfg_insert (hashtable_t *ht, cfg_t *CFG, instr_t *ins)
{
	if (!CFG)
		return NULL;
	cfg_t *new = hashtable_lookup (ht, ins);
	if (!new)
		{
		new = cfg_new (ins);
		return aux_cfg_insert(CFG, new);
		}
else
	{

		for (size_t i = 0; i < CFG->nb_out; i++)
			{
				if (CFG->successor[i]->instruction->address
					 == new->instruction->address)
					return new;
			}
		return aux_cfg_insert(CFG, new);
	}
}


void
cfg_delete (cfg_t *CFG)
{
	if (CFG)
		{
			if (CFG->instruction)
			{
				instr_delete (CFG->instruction);
			}
			if (CFG->successor)
				{
					size_t i = 0;
					while (CFG->successor[i])
						{
							free (CFG->successor[i]);
							i++;
						}
					free (CFG->successor);
				}
			free (CFG);
		}
	return;
}
