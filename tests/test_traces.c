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

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include <errno.h>

#include "traces.h"

#include <stdio.h>

static void
instr_test (__attribute__ ((unused)) void **state)
{
  uint8_t size = 4;
  uintptr_t addr = 0xdeadbeef;
  uint8_t *opcodes = (uint8_t *) "\xbe\xba\xfe\xca";

  /* Testing nominal cases */
  instr_t *instr = instr_new (addr, size, opcodes);
  assert_non_null (instr);

  assert_true (instr_addr (instr) == addr);
  assert_true (instr_size (instr) == size);
  assert_memory_equal (instr_opcodes (instr), opcodes, size);

  instr_delete (instr);

  /* Testing border cases */
  instr = instr_new (addr, 0, opcodes);
  assert_null (instr);
  assert_true (errno == EINVAL);

  instr = instr_new (addr, size, NULL);
  assert_null (instr);
  assert_true (errno == EINVAL);
}

static void
hashtable_test (__attribute__ ((unused)) void **state)
{
  size_t ht_size = 4;
  uint8_t *opcodes1 = (uint8_t *) "\x00\x11\x22\x77",
	  *opcodes2 = (uint8_t *) "\xbb\xcc",
	  *opcodes3 = (uint8_t *) "\xdd\xee\xff",
	  *opcodes4 = (uint8_t *) "\x00\x11\x22\x33",
	  *opcodes5 = (uint8_t *) "\x44\x55\x66\x77",
	  *opcodes6 = (uint8_t *) "\x88\x99\xaa\xbb\xcc\xde\xad\xbe\xef\xca";

  instr_t *instr1 = instr_new (0xdeadbeef, 4, opcodes1),
	  *instr2 = instr_new (0xabad1dea, 2, opcodes2),
	  *instr3 = instr_new (0xcafebabe, 3, opcodes3),
	  *instr4 = instr_new (0xdeadbeef, 4, opcodes4),
	  *instr5 = instr_new (0xf001beef, 5, opcodes5),
	  *instr6 = instr_new (0xdeadbeef, 6, opcodes6),
	  *instr7 = instr_new (0xac001dad, 7, opcodes6),
	  *instr8 = instr_new (0xfedcbaaa, 8, opcodes6),
	  *instr9 = instr_new (0xffffffff, 9, opcodes6),
	  *instr10 = instr_new (0xeeeeeeee, 10, opcodes6),
	  *instr11 = instr_new (0xdddddddd, 4, opcodes6); /* Not inserted */

  /* Testing nominal cases */
  hashtable_t *ht = hashtable_new (ht_size);
  assert_non_null (ht);

  /* First lookup on an empty hashtable */
  assert_false (hashtable_lookup (ht, instr1));

  /* Insert null parameters */
  assert_false (hashtable_insert (NULL, instr1));
  assert_false (hashtable_insert (ht, NULL));

  /* Test insertion */
  assert_true (hashtable_insert (ht, instr1));
  assert_true (hashtable_insert (ht, instr2));
  assert_true (hashtable_insert (ht, instr3));
  assert_true (hashtable_insert (ht, instr4));
  assert_true (hashtable_insert (ht, instr5));
  assert_true (hashtable_insert (ht, instr6));
  assert_true (hashtable_insert (ht, instr7));
  assert_true (hashtable_insert (ht, instr8));
  assert_true (hashtable_insert (ht, instr9));
  assert_true (hashtable_insert (ht, instr10));

  /* Test reinsertion attempt */
  assert_false (hashtable_insert (ht, instr4));

  /* Testing accessors */
  assert_true (hashtable_entries (ht) == 10);
  assert_true (hashtable_collisions (ht) == 6);
  assert_true (hashtable_filled_buckets (ht) == ht_size);

  /* Testing hashtable_lookup */
  assert_false (hashtable_lookup (NULL, instr1));
  assert_false (hashtable_lookup (ht, NULL));

  assert_true (hashtable_lookup (ht, instr1));
  assert_true (hashtable_lookup (ht, instr2));
  assert_true (hashtable_lookup (ht, instr3));
  assert_true (hashtable_lookup (ht, instr4));
  assert_true (hashtable_lookup (ht, instr5));
  assert_true (hashtable_lookup (ht, instr6));
  assert_true (hashtable_lookup (ht, instr7));
  assert_true (hashtable_lookup (ht, instr8));
  assert_true (hashtable_lookup (ht, instr9));
  assert_true (hashtable_lookup (ht, instr10));

  assert_false (hashtable_lookup (ht, instr11));

  /* Cleaning current hashtable */
  hashtable_delete (ht);

  instr_delete (instr11);

  /* Testing border cases */
  ht = hashtable_new (0);
  assert_null (ht);
  assert_true (errno == EINVAL);
}

static void
trace_test (__attribute__ ((unused)) void **state)
{
  uint8_t *opcodes1 = (uint8_t *) "\x00\x11\x22\x77",
	  *opcodes2 = (uint8_t *) "\xbb\xcc",
	  *opcodes3 = (uint8_t *) "\xdd\xee\xff",
	  *opcodes4 = (uint8_t *) "\x00\x11\x22\x33",
	  *opcodes5 = (uint8_t *) "\x44\x55\x66\x77",
	  *opcodes6 = (uint8_t *) "\x88\x99\xaa\xbb\xcc\xde\xad\xbe\xef\xca";

  instr_t *instr1 = instr_new (0xdeadbeef, 4, opcodes1),
	  *instr2 = instr_new (0xabad1dea, 2, opcodes2),
	  *instr3 = instr_new (0xcafebabe, 3, opcodes3),
	  *instr4 = instr_new (0xdeadbeef, 4, opcodes4),
	  *instr5 = instr_new (0xf001beef, 5, opcodes5),
	  *instr6 = instr_new (0xdeadbeef, 6, opcodes6),
	  *instr7 = instr_new (0xac001dad, 7, opcodes6),
	  *instr8 = instr_new (0xfedcbaaa, 8, opcodes6),
	  *instr9 = instr_new (0xffffffff, 9, opcodes6),
	  *instr10 = instr_new (0xeeeeeeee, 10, opcodes6),
	  *instr11 = instr_new (0xdddddddd, 4, opcodes6);

  trace_t *tr = trace_new ();
  assert_non_null (tr);
  trace_delete (tr); /* Delete an empty trace */

  tr = trace_new ();
  assert_non_null (tr);

  assert_true (trace_append (NULL, instr1) == -1 && errno == EINVAL);
  assert_true (trace_append (tr, NULL) == -1 && errno == EINVAL);

  trace_append (tr, instr1);
  trace_delete (tr); /* Delete a trace with only one instruction */

  tr = trace_new ();
  assert_non_null (tr);

  trace_append (tr, instr1);
  trace_append (tr, instr2);
  trace_append (tr, instr3);

  assert_true (trace_get (NULL, 0) == NULL && errno == EINVAL);
  assert_true (trace_get (tr, 0) == instr1);
  assert_true (trace_get (tr, 1) == instr2);
  assert_true (trace_get (tr, 2) == instr3);
  assert_true (trace_get (tr, 3) == NULL);

  trace_t *tr2 = trace_new ();
  assert_non_null (tr2);

  trace_append (tr2, instr1);
  trace_append (tr2, instr2);
  trace_append (tr2, instr3);

  assert_true (trace_compare (NULL, tr) == 0 && errno == EINVAL);
  assert_true (trace_compare (tr, NULL) == 0 && errno == EINVAL);
  assert_true (trace_compare (tr, tr2) == 0);

  trace_delete (tr);
  trace_delete (tr2);
  trace_delete (NULL);

  instr_delete (instr1);
  instr_delete (instr2);
  instr_delete (instr3);
  instr_delete (instr4);
  instr_delete (instr5);
  instr_delete (instr6);
  instr_delete (instr7);
  instr_delete (instr8);
  instr_delete (instr9);
  instr_delete (instr10);
  instr_delete (instr11);
}

int
main (void)
{
  const struct CMUnitTest tests[] = {
      cmocka_unit_test (instr_test),
      cmocka_unit_test (hashtable_test),
      cmocka_unit_test (trace_test),
  };

  return cmocka_run_group_tests (tests, NULL, NULL);
}
