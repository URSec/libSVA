/*===- uaccess.c - SVA Execution Engine -------------------------------------===
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
 * This header file contains functions which implement safe copying to/from
 * untrusted pointers.
 *
 *===------------------------------------------------------------------------===
 */

#include <sva/uaccess.h>

size_t sva_copy_from_user(void* dst, const void __user* src, size_t len) {
  if (!is_valid_user_ptr(src, len)) {
    return len;
  }

  return memcpy_safe(dst, (void __noderef*)src, len);
}

size_t sva_copy_to_user(void __user* dst, const void* src, size_t len) {
  if (!is_valid_user_ptr(dst, len)) {
    return len;
  }

  return memcpy_safe((void __noderef*)dst, src, len);
}

size_t sva_copy_from_kernel(void* dst, const void __kern* src, size_t len) {
  if (!is_valid_kernel_ptr(src, len)) {
    return len;
  }

  return memcpy_safe(dst, (void __noderef*)src, len);
}

size_t sva_copy_to_kernel(void __kern* dst, const void* src, size_t len) {
  if (!is_valid_kernel_ptr(dst, len)) {
    return len;
  }

  return memcpy_safe((void __noderef*)dst, src, len);
}

size_t sva_copy_user_to_kernel(void __kern* dst,
                               const void __user* src,
                               size_t len)
{
  if (!is_valid_user_ptr(src, len)) {
    return len;
  }

  if (!is_valid_kernel_ptr(dst, len)) {
    return len;
  }

  return memcpy_safe((void __noderef*)dst, (void __noderef*)src, len);
}

size_t sva_copy_kernel_to_user(void __user* dst,
                               const void __kern* src,
                               size_t len)
{
  if (!is_valid_kernel_ptr(src, len)) {
    return len;
  }

  if (!is_valid_user_ptr(dst, len)) {
    return len;
  }

  return memcpy_safe((void __noderef*)dst, (void __noderef*)src, len);
}
