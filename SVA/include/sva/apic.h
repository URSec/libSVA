/*===- apic.h - SVA APIC definitions ----------------------------------------===
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
 * This header file contains definitions for the fields of the x86 APIC
 * registers and functions for reading and writing them.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_APIC_H
#define SVA_APIC_H

#include <sva/page.h>
#include <sva/types.h>
#include <sva/msr.h>
#include <sva/util.h>

#define MSR_APIC_BASE ...
#define MSR_X2APIC_REG_BASE     0x800
#define MSR_X2APIC_ID           (MSR_X2APIC_REG_BASE + 0x02)
#define MSR_X2APIC_ISR          (MSR_X2APIC_REG_BASE + 0x10)
#define MSR_X2APIC_EOI          (MSR_X2APIC_REG_BASE + 0x0b)
#define MSR_X2APIC_ICR          (MSR_X2APIC_REG_BASE + 0x30)

struct apic_icr {
  uint8_t vector: 8;

  enum apic_delivery_mode {
    APIC_DM_FIXED,
    APIC_DM_RESERVED0,
    APIC_DM_SMI,
    APIC_DM_RESERVED1,
    APIC_DM_NMI,
    APIC_DM_INIT,
    APIC_DM_STARTUP,
    APIC_DM_RESERVED2,
  } delivery_mode: 3;

  enum apic_destination_mode {
    APIC_DEST_MODE_PHYSICAL,
    APIC_DEST_MODE_LOGICAL,
  } destination_mode: 1;

  enum apic_delivery_status {
    APIC_DELIVERY_IDLE,
    APIC_DELIVERY_PENDING,
  } delivery_status: 1;

  unsigned int _reserved0: 1;

  enum apic_level {
    APIC_LVL_DEASSERT,
    APIC_LVL_ASSERT,
  } level: 1;

  enum apic_trigger_mode {
    APIC_TM_EDGE,
    APIC_TM_LEVEL,
  } trigger_mode: 1;

  unsigned int _reserved1: 2;

  enum apic_destination_shorthand {
    APIC_SHORTHAND_NONE,
    APIC_SHORTHAND_SELF,
    APIC_SHORTHAND_ALL,
    APIC_SHORTHAND_ALLBUTSELF,
  } destination_shorthand: 2;

  unsigned int _reserved2: 12;

  uint32_t dest: 32;
} __attribute__((packed, aligned(8)));

_Static_assert(sizeof(struct apic_icr) == 8, "APIC ICR wrong size");

#define MAKE_IPI_BROADCAST(vec) ((struct apic_icr){     \
    .destination_shorthand = APIC_SHORTHAND_ALLBUTSELF, \
    .destination_mode = APIC_DEST_MODE_PHYSICAL,        \
    .vector = (vec),                                    \
    .delivery_mode = APIC_DM_FIXED,                     \
    .level = APIC_LVL_ASSERT,                           \
})

#define MAKE_INIT_IPI(dest_id) ((struct apic_icr){  \
    .destination_shorthand = APIC_SHORTHAND_NONE,   \
    .destination_mode = APIC_DEST_MODE_PHYSICAL,    \
    .dest = (dest_id),                              \
    .vector = 0,                                    \
    .delivery_mode = APIC_DM_INIT,                  \
    .level = APIC_LVL_ASSERT,                       \
    .trigger_mode = APIC_TM_LEVEL,                  \
    .delivery_status = 0,                           \
    ._reserved0 = 0,                                \
    ._reserved1 = 0,                                \
    ._reserved2 = 0,                                \
})                                                  \

#define MAKE_INIT_DEASSERT_IPI() ((struct apic_icr){  \
    .destination_shorthand = APIC_SHORTHAND_ALL,      \
    .destination_mode = 0,                            \
    .dest = 0,                                        \
    .vector = 0,                                      \
    .delivery_mode = APIC_DM_INIT,                    \
    .level = APIC_LVL_DEASSERT,                       \
    .trigger_mode = APIC_TM_LEVEL,                    \
    .delivery_status = 0,                             \
    ._reserved0 = 0,                                  \
    ._reserved1 = 0,                                  \
    ._reserved2 = 0,                                  \
})                                                    \

#define MAKE_STARTUP_IPI(dest_id, start_addr) ((struct apic_icr){ \
    .destination_shorthand = APIC_SHORTHAND_NONE,                 \
    .destination_mode = APIC_DEST_MODE_PHYSICAL,                  \
    .dest = (dest_id),                                            \
    .vector = (start_addr) >> PG_L1_SHIFT,                        \
    .delivery_mode = APIC_DM_STARTUP,                             \
    .level = APIC_LVL_ASSERT,                                     \
    .trigger_mode = APIC_TM_LEVEL,                                \
    .delivery_status = 0,                                         \
    ._reserved0 = 0,                                              \
    ._reserved1 = 0,                                              \
    ._reserved2 = 0,                                              \
})                                                                \

static inline void apic_send_ipi(struct apic_icr icr) {
  union {
    uint64_t raw;
    struct apic_icr typed;
  } convert = { .typed = icr };
  wrmsr(MSR_X2APIC_ICR, convert.raw);
}

static inline bool apic_isr_test(uint8_t idx) {
  uint32_t reg = rdmsr(MSR_X2APIC_ISR + (idx / 32));
  return !!(reg & (1U << (idx % 32)));
}

static inline void apic_eoi(void) {
  wrmsr(MSR_X2APIC_EOI, 0);
}

#endif /* SVA_APIC_H */
