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
#include <sva/dmap.h>
#include <sva/secmem.h>
#include <sva/page_walk.h>

#define MSR_REG_EFER    0xC0000080      /* MSR for EFER register */

#define align_down(val, align) \
  ((__typeof__(val))((val) & ~((align) - 1)))

#define align_down_pow2(val, align) \
  (align_down((val), (__typeof__(val))1 << (align)))

#define align_up(val, align) ({           \
  __typeof__(align) __a = (align) - 1;    \
  (__typeof__(val))((val) + __a & ~__a);  \
})

#define align_up_pow2(val, align) \
  (align_up((val), (__typeof__(val))1 << (align)))

#define is_aligned(val, align) \
  (((val) & ((align) - 1)) == (__typeof__(val))0)

#define is_aligned_pow2(val, align) \
  (is_aligned((val), (__typeof__(val))1 << (align)))

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
 * Read the %fs.base value
 *
 * @return  The %fs.base value
 */
static inline uintptr_t rdfsbase(void) {
  uintptr_t base;

  asm volatile ("rdfsbase %0" : "=r"(base));

  return base;
}

/**
 * Write the %fs.base value
 *
 * @param base  The new base value
 */
static inline void wrfsbase(uintptr_t base) {
  asm volatile ("wrfsbase %0" :: "r"(base) : "memory");
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
  asm volatile ("wrgsbase %0" :: "r"(base) : "memory");
}

/**
 * Swap the `%gs.base` with the shadow `%gs.base`.
 */
static inline void swapgs(void) {
  asm volatile ("swapgs");
}

/**
 * Load the shadow `%gs.base`.
 *
 * Note: This function returns the current shadow `%gs.base` because it is
 * faster to read it while the bases are swapped for writing than to swap them
 * twice in two separate function calls (one to read, one to write).
 *
 * @param gss The new shadow `%gs.base` to load
 * @return    The current shadow `%gs.base`
 */
static inline uintptr_t wrgsshadow(uintptr_t gss) {
  /*
   * It seems that the best/fastest way to access the GS Shadow register is
   * to do SWAPGS, RD/WRGSBASE, and SWAPGS again. The ISA also provides an
   * MSR for direct access to GS Shadow (alongside the similar MSRs for
   * direct access to FS/GS Base), but it seems that the double-SWAPGS method
   * is preferable (probably for performance?), because that's how Xen does
   * it.
   */

  swapgs();
  uintptr_t old = rdgsbase();
  wrgsbase(gss);
  swapgs();

  return old;
}

/**
 * Get the current shadow `%gs.base`.
 *
 * @return  The current shadown `%gs.base`
 */
static inline uintptr_t rdgsshadow(void) {
  swapgs();
  uintptr_t gss = rdgsbase();
  swapgs();
  return gss;
}

/**
 * Set the alignment check flag.
 *
 * With SMAP enabled, also disallows supervisor-mode access to user-mode
 * virtual addresses.
 */
static inline void stac(void) {
  asm volatile ("stac" ::: "memory");
}

/**
 * Clear the alignment check flag.
 *
 * With SMAP enabled, also allows supervisor-mode access to user-mode virtual
 * addresses.
 */
static inline void clac(void) {
  asm volatile ("clac" ::: "memory");
}

static inline void
sva_check_memory_read (void * memory, unsigned int size) {
#ifdef FreeBSD
  volatile unsigned char value;
  volatile unsigned char * p = (unsigned char *)(memory);

  /*
   * For now, we assume that all memory buffers are less than 4K in size, so
   * they can only be in two pages at most.
   */
  value = p[0];
  value = p[size - 1];
#else
  /*
   * Silence unused parameter warnings.
   */
  (void)memory;
  (void)size;
#endif
} 

/**
 * Check that a memory region does not overlap with secure memory.
 *
 * @param start The start of the memory region to check
 * @param len   The length of the memory region to check
 */
void sva_check_buffer(uintptr_t start, size_t len);

static inline void
sva_check_memory_write (void * memory, unsigned int size) {
#ifdef FreeBSD
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
#else
  /*
   * Silence unused parameter warnings.
   */
  (void)memory;
  (void)size;
#endif
}

/**
 * Save the current interruptability state.
 *
 * @return  The current interruptability state.
 */
static inline unsigned long sva_save_in_critical(void) {
  unsigned long rflags;
  asm ("pushfq\n\t"
       "popq %0\n\t"
       : "=r"(rflags));
  return rflags;
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

static inline void
bochsBreak (void) {
  __asm__ __volatile__ ("xchg %bx, %bx\n");
  return;
}

/**
 * Read the current value of the processor's time-stamp counter.
 *
 * @return  The current TSC value
 */
static inline uint64_t sva_read_tsc(void) {
  return __builtin_ia32_rdtsc();
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

/**
 * An expensive nop.
 *
 * Useful in spin-wait loops to delay iterations.
 */
static inline void pause() {
  __builtin_ia32_pause();
}

#ifdef __cplusplus
}
#endif

#endif /* _SVA_UTIL_H */
