/*===- checks.c - SVA Execution Engine  =-----------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements run-time checks that the instrumentation pass does not
 * inline directly.
 *
 *===----------------------------------------------------------------------===
 */

#include <sva/types.h>
#include <sva/mmu.h>
#include <sva/secmem.h>
#include <sva/self_profile.h>
#include <sva/util.h>

void sva_check_buffer(uintptr_t start, size_t len) {
  SVA_PROF_ENTER();

  /*
   * Compute the last address of the buffer.
   */
  uintptr_t end = start + len;

  SVA_ASSERT(!is_secure_memory_addr(start) && !is_secure_memory_addr(end) &&
             (start - SECMEMSTART <= end - SECMEMSTART),
    "SVA: FATAL: Invalid buffer access: 0x%016lx 0x%016lx\n", start, end);

#ifdef FreeBSD
  /*
   * Check whether the pointer is within SVA internal memory.
   */
  extern char _svastart[];
  extern char _svaend[];
  size_t svamemlen = _svaend - _svastart;

  /*
   * Treat the beginning of the ghost memory as address zero.  We have
   * overlap if either the first or last byte of the buffer, when normalized
   * to ghost memory, falls within the range of ghost memory.
   */
  uintptr_t sstart = start - (uintptr_t)_svastart;
  uintptr_t send   = end   - (uintptr_t)_svastart;
  SVA_ASSERT(sstart >= svamemlen && send >= svamemlen && sstart <= send,
    "SVA: FATAL: Invalid buffer access: %lx %lx\n", start, end);
#endif

  SVA_PROF_EXIT(check_buffer);
}

void __attribute__((noreturn)) abort(void) {
  SVA_ASSERT_UNREACHABLE("SVA: FATAL: CFI check failure\n");
}
