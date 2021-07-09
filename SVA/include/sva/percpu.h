/*===- percpu.h - SVA Execution Engine  =------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2021.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * Constants and declarations for SVA's per-CPU region.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_PERCPU_H
#define _SVA_PERCPU_H

#include <sva/icontext.h>
#include <sva/page.h>

struct percpu_alloc {
  tss_t tss;

  struct sva_tls_area tls_area;

  struct CPUState cpu_state;
};

/*
 * The linker script gives us 16-byte alignment.
 */
_Static_assert(alignof(struct percpu_alloc) <= 16, "Per-CPU data underaligned");

#endif /* _SVA_PERCPU_H */
