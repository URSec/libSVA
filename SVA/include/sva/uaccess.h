/*===- uaccess.h - SVA safe user and kernel pointer access ------------------===
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
 * This header file contains declarations for functions which allow safe
 * accesses through user and kernel pointers.
 *
 *===------------------------------------------------------------------------===
 */

#ifndef _SVA_UACCESS_H
#define _SVA_UACCESS_H

#include <sva/types.h>
#include <sva/assert.h>
#include <sva/secmem.h>

/**
 * Check if a userspace pointer is in a valid address space region.
 */
static inline bool is_valid_user_ptr(const void __user* ptr, size_t size) {
  uintptr_t start = (uintptr_t)ptr;
  uintptr_t end =
    size > 0 ? (uintptr_t)((const char __user*)ptr + size - 1) : start;

  if (end < start) {
    // Overflow
    return false;
  }

#ifdef XEN
  /*
   * Xen PV guest kernels live in the upper canonical half.
   */
  if (start >= GUESTSTART) {
    return true;
  }
#endif

  /*
   * Userspace is allowed to access its own canonical half and the ghost memory
   * region (a subset of the secure memory region reserved to userspace).
   */
  return end < USEREND || (is_ghost_addr(start) && is_ghost_addr(end));
}

/**
 * Check if a kernelspace pointer is in a valid address space region.
 */
static inline bool is_valid_kernel_ptr(const void __kern* ptr, size_t size) {
  uintptr_t start = (uintptr_t)ptr;
  uintptr_t end =
    size > 0 ? (uintptr_t)((const char __kern*)ptr + size - 1) : start;

  /*
   * The kernel is allowed to access anything not in the secure memory region.
   */
  return start <= end // Overflow
    && !is_secure_memory_addr(start) && !is_secure_memory_addr(end)
    && (start >= SECMEMEND || end < SECMEMSTART);
}

/**
 * Copy memory with fault recovery.
 *
 * Preconditions:
 *  The pointers `dst` and `src` have been vetted to be in appropriate regions
 *  of the address space for their origins.
 *
 * @param dst   The buffer to copy data into
 * @param src   The buffer to copy data from
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t memcpy_safe(void __noderef* dst, const void __noderef* src, size_t len);

/**
 * Copy a range of memory from userspace into SVA.
 *
 * @param dst   A pointer to a buffer of size at least `len`
 * @param src   A userspace pointer
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_from_user(void* dst, const void __user* src, size_t len);

/**
 * Copy a range of memory from SVA into userspace.
 *
 * @param dst   A userspace pointer
 * @param src   A pointer to a buffer of size at least `len`
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_to_user(void __user* dst, const void* src, size_t len);

/**
 * Copy a range of memory from kernelspace into SVA.
 *
 * @param dst   A pointer to a buffer of size at least `len`
 * @param src   A kernelspace pointer
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_from_kernel(void* dst, const void __kern* src, size_t len);

/**
 * Copy a range of memory from SVA into kernelspace.
 *
 * @param dst   A kernelspace pointer
 * @param src   A pointer to a buffer of size at least `len`
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_to_kernel(void __kern* dst, const void* src, size_t len);

/**
 * Copy a range of memory from userspace into kernelspace.
 *
 * @param dst   A kernelspace pointer
 * @param src   A userspace pointer
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_user_to_kernel(void __kern* dst,
                               const void __user* src,
                               size_t len);

/**
 * Copy a range of memory from kernelspace into userspace.
 *
 * @param dst   A userspace pointer
 * @param src   A kernelspace pointer
 * @param len   The amount of bytes to copy
 * @return      The amount of bytes left to copy (0 if successful)
 */
size_t sva_copy_kernel_to_user(void __user* dst,
                               const void __kern* src,
                               size_t len);

#endif /* _SVA_UACCESS_H */
