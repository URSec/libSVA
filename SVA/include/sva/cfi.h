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

/* CFI label: endbr64 */
#define CHECKLABEL 0xfa1e0ff3

#ifdef __ASSEMBLER__

/* Macro for call */
#define CALLQ(x) .bundle_lock align_to_end; \
                 callq x; \
                 .bundle_unlock; \
                 RETTARGET

/* Macro for start of function */
#define STARTFUNC endbr64

#define RETTARGET endbr64

/* Macro for return */
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

#endif /* __ASSEMBLER__ */

#endif /* SVA_CFI_H */
              /* addq  $0x8, %rcx ; \ */
