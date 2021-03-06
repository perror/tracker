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

#include "config.h"

#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <elf.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>

#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <capstone/capstone.h>

#include <executables.h>
#include <traces.h>

/* In amd64, maximum bytes for an opcode is 15 */
#define MAX_OPCODE_BYTES 16

/* Global variables for this module */
static bool debug = false;   /* 'debug' option flag */
static bool verbose = false; /* 'verbose' option flag */
static FILE *output = NULL;  /* output file (default: stdout) */

/* Get current instruction pointer address */
static uintptr_t
get_current_ip (struct user_regs_struct *regs)
{
#if defined(__x86_64__) /* amd64 architecture */
  return regs->rip;
#elif defined(__i386__) /* i386 architecture */
  return regs->eip;
#else
#error Cannot build, we only support: x86-64 and i386 architectures
#endif
}

int
main (int argc, char *argv[], char *envp[])
{
  /* Getting program name */
  const char *program_name = basename (argv[0]);

  /* Initializing output to its default */
  output = stdout;

  /* Options parser settings */
  opterr = 0; /* Mute error message from getopt() */
  const char *opts = "dhio:vV";

  bool intel = false;

  const struct option long_opts[] = {{"debug", no_argument, NULL, 'd'},
				     {"intel", no_argument, NULL, 'i'},
				     {"output", required_argument, NULL, 'o'},
				     {"verbose", no_argument, NULL, 'v'},
				     {"version", no_argument, NULL, 'V'},
				     {"help", no_argument, NULL, 'h'},
				     {NULL, 0, NULL, 0}};

  const char *usage_msg =
      "Usage: %1$s [-o FILE|-i|-v|-d|-V|-h] [--] EXEC [ARGS]\n"
      "Trace the execution of EXEC on the given arguments ARGS\n"
      "\n"
      " -o FILE,--output FILE  write result to FILE\n"
      " -i,--intel             switch to intel syntax (default: at&t)\n"
      " -v,--verbose           verbose output\n"
      " -d,--debug             debug output\n"
      " -V,--version           display version and exit\n"
      " -h,--help              display this help\n";

  /* Parsing options */
  int optc;
  while ((optc = getopt_long (argc, argv, opts, long_opts, NULL)) != -1)
    switch (optc)
      {
      case 'o': /* Output file */
	output = fopen (optarg, "we");
	if (!output)
	  err (EXIT_FAILURE, "error: cannot open file '%s'", optarg);
	break;

      case 'i': /* intel syntax mode */
	intel = true;
	break;

      case 'd': /* Debug mode */
	debug = true;
	break;

      case 'v': /* Verbosity mode */
	verbose = true;
	break;

      case 'V': /* Display version number and exit */
	fprintf (stdout, "%s %s\n", program_name, VERSION);
	fputs ("Trace the execution of a program on the given input\n", stdout);
	exit (EXIT_SUCCESS);
	break;

      case 'h': /* Display usage and exit */
	fprintf (stdout, usage_msg, program_name);
	exit (EXIT_SUCCESS);
	break;

      default:
	errx (EXIT_FAILURE, "error: invalid option '%s'!", argv[optind - 1]);
      }

  /* Checking that extra arguments are present */
  if (optind > (argc - 1))
    errx (EXIT_FAILURE, "error: missing argument: an executable is required!");

  /* Extracting the complete argc/argv[] of the traced command */
  int exec_argc = argc - optind;
  char *exec_argv[exec_argc + 1];
  for (int i = 0; i < exec_argc; i++)
    {
      exec_argv[i] = argv[optind + i];
    }
  exec_argv[exec_argc] = NULL;

  /* Perfom various checks on the executable file */
  executable_t *exec = executable_new (exec_argv[0]);

  if (verbose)
    {
      fprintf (output, "* Executable: %s\n", exec_argv[0]);
      fprintf (output, "* Architecture: ");
      executable_print_arch (exec, output);
      fputs ("\n", output);
    }

  /* Display the traced command */
  fprintf (output, "%s: starting to trace '", program_name);
  for (int i = 0; i < exec_argc - 1; i++)
    {
      fprintf (output, "%s ", exec_argv[i]);
    }
  fprintf (output, "%s'\n\n", exec_argv[exec_argc - 1]);

  /* Forking and tracing */
  pid_t child = fork ();
  if (child == -1)
    errx (EXIT_FAILURE, "error: fork failed!");

  /* Initialized and start the child */
  if (child == 0)
    {
      /* Disabling ASLR */
      personality (ADDR_NO_RANDOMIZE);

      /* Start tracing the process */
      if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) == -1)
	errx (EXIT_FAILURE,
	      "error: cannot operate from inside a ptrace() call!");

      /* Starting the traced executable */
      execve (exec_argv[0], exec_argv, envp);
    }

  /* Parent process */
  int status;
  uint8_t buf[MAX_OPCODE_BYTES];
  uintptr_t ip;
  struct user_regs_struct regs;

  /* Initializing Capstone disassembler */
  csh handle;
  cs_insn *insn;
  size_t count;

  cs_mode exec_mode = 0;
  switch (executable_arch (exec))
    {
    case x86_32_arch:
      exec_mode = CS_MODE_32;
      break;

    case x86_64_arch:
      exec_mode = CS_MODE_64;
      break;

    default:
      errx (EXIT_FAILURE, "error: '%s' unsupported architecture", exec_argv[0]);
    }

  /* Initialize the assembly decoder */
  if (cs_open (CS_ARCH_X86, exec_mode, &handle) != CS_ERR_OK)
    errx (EXIT_FAILURE, "error: cannot start capstone disassembler");

  /* Set syntax flavor output */
  if (intel)
    cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
  else
    cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

  /* Main disassembling loop */
  size_t instr_count = 0;
  hashtable_t *ht = hashtable_new (DEFAULT_HASHTABLE_SIZE);
  if (ht == NULL)
    err (EXIT_FAILURE, "error: cannot create hashtable");

  while (true)
    {
      /* Waiting for child process */
      wait (&status);
      if (WIFEXITED (status))
	break;

      /* Get instruction pointer */
      ptrace (PTRACE_GETREGS, child, NULL, &regs);

      /* Printing instruction pointer */
      ip = get_current_ip (&regs);
      fprintf (output, "0x%" PRIxPTR "  ", ip);

      /* Get the opcode from memory */
      for (size_t i = 0; i < MAX_OPCODE_BYTES; i += 8)
	{
	  long *ptr = (long *) &(buf[i]);
	  *ptr = ptrace (PTRACE_PEEKDATA, child, ip + i, NULL);
	}

      /* Get the mnemonic from decoder */
      count = cs_disasm (handle, &(buf[0]), MAX_OPCODE_BYTES, 0x1000, 0, &insn);
      if (count > 0)
	{
	  /* Display the bytes */
	  for (size_t i = 0; i < insn[0].size; i++)
	    fprintf (output, " %02x", buf[i]);

	  /* Pretty printing and formating */
	  if (insn[0].size != 8 && insn[0].size != 11)
	    fprintf (output, "\t");

	  for (int i = 0; i < 4 - (insn[0].size / 3); i++)
	    fprintf (output, "\t");

	  /* Display mnemonic and operand */
	  fprintf (output, "%s  %s", insn[0].mnemonic, insn[0].op_str);
	  fprintf (output, "\n");

	  /* Create the instr_t structure */
	  instr_t *instr = instr_new (ip, insn[0].size, buf);
	  if (!instr)
	    err (EXIT_FAILURE, "error: cannot create instruction: ");

	  if (!hashtable_insert (ht, instr))
	    {
	      if (errno != 0)
		err (EXIT_FAILURE, "error:");
	      instr_delete (instr);
	    }

	  /* Free capstone instruction structure */
	  cs_free (insn, count);

	  /* Updating counters */
	  instr_count++;
	}

      /* Continue to next instruction... */
      /* Note that, sometimes, ptrace(PTRACE_SINGLESTEP) returns '-1'
       * to notify that the child process did not respond quick enough,
       * we have to wait for ptrace() to return '0'. */
      while (ptrace (PTRACE_SINGLESTEP, child, NULL, NULL))
	;
    }

  fprintf (output,
	   "\n"
	   "\tStatistics about this run\n"
	   "\t=========================\n"
	   "* #instructions executed:    %zu\n"
	   "* #unique instructions:      %zu\n"
	   "* #hashtable buckets:        %zu\n"
	   "* #hashtable filled buckets: %zu\n"
	   "* #hashtable collisions:     %zu\n",
	   instr_count, hashtable_entries (ht), (size_t) DEFAULT_HASHTABLE_SIZE,
	   hashtable_filled_buckets (ht), hashtable_collisions (ht));

  /* Cleaning memory */
  cs_close (&handle);
  hashtable_delete (ht);
  executable_delete (exec);

  if (output != stdout)
    fclose (output);

  return EXIT_SUCCESS;
}
