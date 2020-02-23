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
  size_t ht_size = 1024;

  hashtable_t *ht = hashtable_new (ht_size);
  assert_non_null (ht);

  hashtable_delete (ht);
}

int
main (void)
{
  const struct CMUnitTest tests[] = {
      cmocka_unit_test (instr_test),
      cmocka_unit_test (hashtable_test),
  };

  return cmocka_run_group_tests (tests, NULL, NULL);
}
