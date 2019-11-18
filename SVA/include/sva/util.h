/*===- util.h - SVA Utilities ---------------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This header file contains utility definitions that are exported to the
 * SVA Execution Engine but not to the operating system kernel.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef _SVA_UTIL_H
#define _SVA_UTIL_H

#include <sva/types.h>

#include <sva/cr.h>
#include <sva/secmem.h>

#define MSR_REG_EFER    0xC0000080      /* MSR for EFER register */

#ifdef __cplusplus
extern "C" {
#endif

/*
 *****************************************************************************
 * Low level register read/write functions
 *****************************************************************************
 */

/**
 * Read the value in an MSR.
 *
 * @param msr The index of the MSR to read
 * @return    The value in the MSR
 */
static inline uint64_t rdmsr(uint32_t msr) {
  uint32_t low, high;
  __asm __volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (msr));

  return (low | ((uint64_t)high << 32));
}

/**
 * Set the value in an MSR.
 *
 * @param msr The index of the MSR to read
 * @param val The value to set in the MSR
 */
static inline void wrmsr(uint32_t msr, uint64_t val) {
  uint32_t low, high;
  low = val;
  high = val >> 32;
  __asm __volatile("wrmsr" : : "a" (low), "d" (high), "c" (msr));
}

/**
 * Read the value in the Extended Feature Enable Register (EFER).
 *
 * @return  The current value of EFER
 */
static inline uint64_t read_efer(void) {
  return rdmsr(MSR_REG_EFER);
}

/**
 * Disable use of the FPU.
 */
static inline void fpu_disable(void) {
  /*
   * Unset the FPU emulation bit and set the task-switched and monitor bits.
   */
  write_cr0((read_cr0() & ~CR0_EM) | CR0_TS | CR0_MP);
}

/**
 * Enable use of the FPU.
 */
static inline void fpu_enable(void) {
  /*
   * Clear the task-switched bit.
   */
  asm volatile ("clts");
}

/**
 * Read the %gs.base value
 *
 * @return  The %gs.base value
 */
static inline uintptr_t rdgsbase(void) {
  uintptr_t base;

  asm volatile ("rdgsbase %0" : "=r"(base));

  return base;
}

/**
 * Write the %gs.base value
 *
 * @param base  The new base value
 */
static inline void wrgsbase(uintptr_t base) {
  asm volatile ("wrgsbase %0" :: "r"(base));
}

static inline void
sva_check_memory_read (void * memory, unsigned int size) {
  volatile unsigned char value;
  volatile unsigned char * p = (unsigned char *)(memory);

  /*
   * For now, we assume that all memory buffers are less than 4K in size, so
   * they can only be in two pages at most.
   */
  value = p[0];
  value = p[size - 1];
  return;
} 

static inline void
sva_check_memory_write (void * memory, unsigned int size) {
  volatile unsigned char value1;
  volatile unsigned char value2;
  volatile unsigned char * p = (unsigned char *)memory;

  /*
   * For now, we assume that all memory buffers are less than 4K in size, so
   * they can only be in two pages at most.
   */
  value1 = p[0];
  p[0] = value1;
  value2 = p[size - 1];
  p[size - 1] = value2;
  return;
}

/*
 * Function: sva_enter_critical()
 *
 * Description:
 *  Enter an SVA critical section.  This basically means that we need to
 *  disable interrupts so that the intrinsic acts like a single,
 *  uninterruptable instruction.
 */
static inline unsigned long
sva_enter_critical (void) {
  unsigned long rflags;
  __asm__ __volatile__ ("pushfq\n"
                        "popq %0\n"
                        "cli\n" : "=r" (rflags));
  return rflags;
}

/*
 * Function: sva_exit_critical()
 *
 * Description:
 *  Exit an SVA critical section.  This basically means that we need to
 *  enable interrupts if they had been enabled before the intrinsic was
 *  executed.
 */
static inline void
sva_exit_critical (unsigned long rflags) {
  if (rflags & 0x00000200)
    __asm__ __volatile__ ("sti":::"memory");
  return;
}

/**
 * Determine if a virtual address is within the secure memory region.
 *
 * @param p The virtual address to test
 * @return  Whether or not `p` is in the secure memory region
 */
static inline bool
isInSecureMemory(uintptr_t p) {
  return SECMEMSTART <= p && p < SVADMAPEND;
}

static inline void
bochsBreak (void) {
  __asm__ __volatile__ ("xchg %bx, %bx\n");
  return;
}

/*
 * Function: sva_read_tsc
 *
 * Descripton:
 *  Reads the processor time-stamp counter.
 *
 * Return value:
 *  The current value of the time-stamp counter.
 * 
 */
static inline uint64_t sva_read_tsc (void) {
  uint64_t hi, lo;

  __asm__ __volatile__ ("rdtsc\n" : "=a"(lo), "=d"(hi));

  return lo | (hi << 32);
}

/*
 * Function: sva_store_tsc
 *
 * Descripton:
 * Writes the contents of registers EDX:EAX into 
 * the 64-bit model specific register (MSR) specified in the ECX register.
 *
 */
static inline void
sva_store_tsc (uint64_t lo, uint64_t hi) {
  __asm__ __volatile__ ("wrmsr\n" :: "a" (lo), "d" (hi), "c" (0x10));
}

#define SVA_API_NUM 55 //54 

extern unsigned tsc_read_enable;
extern unsigned tsc_read_enable_sva;
extern uint64_t sva_tsc_val[SVA_API_NUM];
extern uint64_t sva_call_freq[SVA_API_NUM];
extern uint64_t wp_num;
extern uint64_t as_num;

enum SVA_OS_NAME
{
  sva_trapframe_api = 0,
  sva_syscall_trapframe_api,
  sva_checkptr_api,
  sva_init_primary_api,
  sva_init_secondary_api,
  sva_iunwind_1_api, 
  sva_iunwind_2_api,
  sva_invokestrncpy_1_api,
  sva_invokestrncpy_2_api,
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
  page_entry_store_api,
};

static inline void
clear_tsc (void) {
  if (tsc_read_enable_sva)
    sva_store_tsc(0, 0);
}

static inline void 
record_tsc(int index, uint64_t tsc_tmp) {
  if (tsc_read_enable_sva) {
     sva_tsc_val[index] += (uint64_t) tsc_tmp;
     sva_call_freq[index] ++;
  }
}

static inline void
init_sva_counter(void) {
  int i;
  for (i = 0; i < SVA_API_NUM; i++)
    sva_tsc_val[i] = sva_call_freq[i] = 0;
  wp_num = as_num = 0;
}

/*
 * Function: sva_random()
 *
 * Description:
 *  Random number generator in SVA. Current implementation uses the rdrand
 *  instruction to generate a 64-bit random number.
 */
static inline unsigned long
sva_random(void) {
  unsigned long rand;
  __asm__ __volatile__ ("1: rdrand %0\n"
			"jae 1b\n" : "=r" (rand));
  return rand;
}

#ifdef __cplusplus
}
#endif

#endif /* _SVA_UTIL_H */
