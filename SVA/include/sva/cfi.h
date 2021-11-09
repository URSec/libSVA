/*===- cfi.h - SVA Execution Engine  =-------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file defines macros that can be used to add CFI checks and labels to
 * hand-written assembly code.
 *
 *===----------------------------------------------------------------------===
 */

#ifndef SVA_CFI_H
#define SVA_CFI_H

#define CFI_BUNDLE_SIZE 32

/* CFI label: endbr64 */
#define CFI_LABEL 0xfa1e0ff3
#define CHECKLABEL CFI_LABEL

#ifdef __ASSEMBLER__

#include <sva/asm-macros.h>

/* Macro for call */
#define CALLQ(x) .bundle_lock align_to_end; \
                 callq x; \
                 .bundle_unlock; \
                 RETTARGET

/* Macro for start of function */
#define STARTFUNC endbr64

#define RETTARGET endbr64

/* Macro for return */
#ifdef FreeBSD

#define RETQ  movq  (%rsp), %rcx ; \
              movl  $0xffffff80, %edx ; \
              shlq   $32, %rdx ; \
              orq   %rdx, %rcx ; \
              addq  $8, %rsp ; \
              cmpl  $CHECKLABEL, (%rcx) ; \
              jne 23f ; \
              jmpq  *%rcx ; \
              xchg %bx, %bx ; \
              23: movq $0xfea, %rax;

#else

.macro RETQ
  /*
   * NB: We can only use registers which are caller-saved and whihc are not
   * used to pass return values. This gives us `%rsi`, `%rdi`, and `%r8` -
   * `%r11`.
   */
  popq %rsi
  andq $-32, %rsi
  cmpl $CHECKLABEL, (%rsi)
  jne  1001f
  jmpq *%rsi
1001:
  call abort@plt
.endm

#endif

#else

#include <sva/types.h>
#include <sva/uaccess.h>
#include <sva/util.h>

/**
 * Check that a kernel function has a valid CFI label.
 */
static bool is_valid_kernel_fn(void __kern* fn) {
  if (!is_ptr_aligned(fn, CFI_BUNDLE_SIZE)) {
    return false;
  }

  uint32_t label;
  if (sva_copy_from_kernel(&label, fn, sizeof(label)) != 0) {
    return false;
  }

  return label == CFI_LABEL;
}

#endif /* __ASSEMBLER__ */

#endif /* SVA_CFI_H */
