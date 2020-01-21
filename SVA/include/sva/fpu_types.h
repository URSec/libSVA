/*===- fpu_types.h - SVA x87, SSE, AVX, and XSAVE type definitions ----------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2020.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header file contains definitions and utilities for the x87, SSE, AVX,
 * and XSAVE extentions.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_FPU_TYPES_H
#define _SVA_FPU_TYPES_H

#include <sva/types.h>

#define XCR0_X87            (1U << 0)
#define XCR0_SSE            (1U << 1)
#define XCR0_AVX            (1U << 2)
#define XCR0_MPXBND         (1U << 3)
#define XCR0_MPXCSR         (1U << 4)
#define XCR0_AVX512MASK     (1U << 5)
#define XCR0_AVX512HIGH256  (1U << 6)
#define XCR0_AVX512HIGHZMM  (1U << 7)

#define XSTATE_XCOMP_COMPRESSED (1UL << 63)

typedef struct {
  char reg[10];
} __attribute__((__aligned__(16))) x87_reg;

typedef struct {
  char reg[16];
} __attribute__((__aligned__(16))) xmm_reg;

typedef struct {
  char reg[32];
} __attribute__((__aligned__(32))) ymm_reg;

typedef struct {
  char reg[64];
} __attribute__((__aligned__(64))) zmm_reg;

typedef char ymm_high[16];

typedef char zmm_high[32];

typedef struct {
  uint64_t low;
  uint64_t high;
} __attribute__((__aligned__(16))) mpx_bndreg;

struct xsave_legacy {
  uint16_t x87_control_word;
  uint16_t x87_status_word;
  uint8_t x87_abridged_tag_word;
  uint16_t x87_last_opcode;
  union {
    struct {
      uint32_t low;
      uint16_t segment;
    };
    uint64_t full;
  } x87_last_instruction;
  union {
    struct {
      uint32_t low;
      uint16_t segment;
    };
    uint64_t full;
  } x87_last_operand;
  uint32_t mxcsr;
  uint32_t mxcsr_mask;
  x87_reg st[8];
  xmm_reg xmm[16];
  char _rsvd[48];
  char _unused[48];
} __attribute__((__aligned__(64)));

struct xsave_header {
  uint64_t xstate_bv;
  uint64_t xcomp_bv;
  uint64_t _rsvd[6];
};

struct xsave_avx {
  ymm_high ymm_h[16];
};

struct xsave_avx512_opmask {
  uint64_t k[8];
};

struct xsave_avx512_zmm_high256 {
  zmm_high zmm_h[16];
};

struct xsave_avx512_high_zmm {
  zmm_reg high_zmm[16];
};

struct xsave_mpx_bndreg {
  mpx_bndreg bnd[4];
};

struct xsave_mpx_bndcsr {
  uint64_t bnd_cfg_user;
  uint64_t bnd_status;
};

struct xsave_area {
  struct xsave_legacy legacy;
  struct xsave_header header;
  char extended_region[0]; /* Size and format depend on header flags */
} __attribute__((__aligned__(64)));

union xsave_area_max {
  struct xsave_area inner;

  /*
   * TODO: Calculate based on enabled features (requires dynamically allocating
   * xsave areas). Intel(R) Xeon(R) Silver 4208 uses 2696B for all extended states.
   */
  char _buf[4096];
};

#endif /* _SVA_FPU_TYPES_H */

