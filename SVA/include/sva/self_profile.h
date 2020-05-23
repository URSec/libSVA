/*===- self_profile.h - SVA Self-Profiling Utilities ------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * Copyright (c) The University of Rochester, 2019.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This header file contains definitions and utilities used by SVA's
 * self-profiling functionality.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef SVA_SELF_PROFILE_H
#define SVA_SELF_PROFILE_H

#include <sva/asmconfig.h>
#include <sva/types.h>
#include <sva/util.h>

#ifdef SVA_SELF_PROFILE

enum SVA_OS_NAME {
  sva_trapframe_api,
  sva_syscall_trapframe_api,
  sva_checkptr_api,
  sva_init_primary_api,
  sva_init_secondary_api,
  sva_iunwind_1_api,
  sva_iunwind_2_api,
  sva_translate_1_api,
  sva_translate_2_api,
  sva_translate_3_api,
  sva_icontext_getpc_api,
  sva_ipush_function5_1_api,
  sva_ipush_function5_2_api,
  sva_ipush_function5_3_api,
  sva_swap_integer_1_api,
  sva_swap_integer_2_api,
  sva_swap_integer_3_api,
  sva_swap_user_integer_1_api,
  sva_swap_user_integer_2_api,
  sva_swap_user_integer_3_api,
  sva_ialloca_api,
  sva_load_icontext_1_api,
  sva_load_icontext_2_api,
  sva_load_icontext_3_api,
  sva_save_icontext_1_api,
  sva_save_icontext_2_api,
  sva_save_icontext_3_api,
  sva_reinit_icontext_1_api,
  sva_reinit_icontext_2_api,
  sva_reinit_icontext_3_api,
  sva_release_stack_1_api,
  sva_release_stack_2_api,
  sva_init_stack_api,
  sva_check_buffer_api,
  sva_getCPUState_1_api,
  sva_getCPUState_2_api,
  sva_icontext_setretval_api,
  sva_icontext_restart_api,
  sva_register_general_exception_api,
  sva_register_memory_exception_api,
  sva_register_interrupt_api,
  sva_mm_load_pgtable_api,
  sva_load_cr0_api,
  sva_mmu_init_api,
  sva_declare_l1_page_api,
  sva_declare_l2_page_api,
  sva_declare_l3_page_api,
  sva_declare_l4_page_api,
  sva_remove_page_1_api,
  sva_remove_page_2_api,
  sva_remove_mapping_api,
  sva_update_l1_mapping_api,
  sva_update_l2_mapping_api,
  sva_update_l3_mapping_api,
  sva_update_l4_mapping_api,
  sva_ghost_fault_api,
  sva_page_entry_store_api,
  SVA_API_NUM,
};

extern bool tsc_read_enable;
extern bool tsc_read_enable_sva;
extern uint64_t sva_tsc_val[SVA_API_NUM];
extern uint64_t sva_call_freq[SVA_API_NUM];
extern uint64_t wp_num;
extern uint64_t as_num;

/**
 * Record the time taken by an SVA API call.
 *
 * @param index The SVA API which was called
 * @param time  The amount of time the call took.
 */
static inline void record_tsc(int index, uint64_t time) {
  if (tsc_read_enable_sva) {
     sva_tsc_val[index] += time;
     sva_call_freq[index]++;
  }
}

/**
 * Initialize SVA's self-profiling infrastructure.
 */
void init_sva_counter(void);

#define SVA_PROF_ENTER()                \
  uint64_t tsc_tmp = 0;                 \
  if (tsc_read_enable_sva) {            \
    tsc_tmp = sva_read_tsc();           \
  };

#define SVA_PROF_EXIT(name)                                             \
  (record_tsc(sva_##name##_api, sva_read_tsc() - tsc_tmp))

#define SVA_PROF_EXIT_MULTI(name, variant)                              \
  (record_tsc(sva_##name##_##variant##_api, sva_read_tsc() - tsc_tmp))

#else

#define SVA_PROF_ENTER() ((void)0)

#define SVA_PROF_EXIT(name) ((void)0)

#define SVA_PROF_EXIT_MULTI(name, variant) ((void)0)

#endif

#endif /* SVA_SELF_PROFILE_H */
