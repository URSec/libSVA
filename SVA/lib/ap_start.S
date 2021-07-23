/*===- ap_boot.S - SVA AP Startup Code --------------------------------------===
 *
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 *
 *===------------------------------------------------------------------------===
 *
 * This file contains code that is executed by an AP when it first comes online.
 *
 *===------------------------------------------------------------------------===
 */

#define SVA_NO_CFI

#include <sva/asmconfig.h>
#include <sva/asm-macros.h>
#include <sva/cr.h>
#include <sva/msr.h>

#define start_sym(sym) (sym - ap_start)

	.section .text.page_aligned, "ax", @progbits

/*
 * Initial entry point for the AP.
 *
 * When it comes online, the AP will start executing here, in real mode, with
 * interrupts disabled. We need to set up a GDT to get into protected mode.
 */
	.code16
ENTRY(ap_start)
	/*
	 * Copy our code segment into our data and stack segments.
	 */
	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %ss

	/*
	 * Load an empty IDT. Otherwise, the CPU will assume there is an IDT at
	 * 0x0.
	 */
	lidtl	start_sym(ap_start_idt_desc)

	/*
	 * Load the ap startup global descriptor table
	 */
	lgdtl	start_sym(ap_start_gdt_desc)

	/*
	 * Enable long mode in EFER.
	 */
	WRMSR_LO $MSR_EFER, $SVA_EFER

	/*
	 * Enable PAE and PGE in `%cr4`. PAE is necessary for long-mode paging.
	 */
	movl	$SVA_BOOT_CR4, %eax
	mov	%eax, %cr4

	/*
	 * Load the root page table pointer that the BSP gave us
	 */
	movl	start_sym(ap_start_pt), %eax
	mov	%eax, %cr3

	/*
	 * Enable protected mode and long jump to a 64-bit code segment. Note
	 * that we must perform the long jump immediately upon enabling
	 * protected mode (Intel Software Developer's Manual, Volume 3, 9.9.1).
	 * We also enable caching, write protection, alignment checking, and
	 * native FPU error reporting here.
	 */
	movl	$SVA_CR0, %eax
	mov	%eax, %cr0

	/*
	 * We use a call gate in order to get into 64-bit mode. This eliminates
	 * the need to have a 64-bit portion of the startup trampoline, which
	 * is beneficial because the trampoline code may be relocated anywhere
	 * in the first 1MB of memory, meaning the target of the long jump
	 * would need to be adjusted at run-time. By using a call gate, no
	 * adjustment is necessary, because the target is at a fixed address.
	 *
	 * Note that, when using a call gate, the offset is not used by the
	 * processor. However, it is still required by the instruction format.
	 */
	ljmpl	$0x10, $0
END(ap_start)

/*
 * GDT for AP bootstrap
 */
	.p2align 3
GLOBL(ap_start_gdt)
	.quad 0x0000000000000000	/* Null descriptor */
	.quad 0x00af9b000000ffff	/* 64-bit ring 0 code segment */
	.quad 0x0			/* Call gate for jump to 64-bit mode */
	.quad 0x0			/* Upper half of previous */
END(ap_start_gdt)
GLOBL(ap_start_gdt_desc)
	.word 0x1f			/* Limit: 4 8-byte entries */
	.long start_sym(ap_start_gdt)	/* Base (adjusted during relocation) */
END(ap_start_gdt_desc)
GLOBL(ap_start_idt_desc)
	.word 0x0
	.long 0x0
END(ap_start_idt_desc)

/*
 * The processor which sends us our startup IPI will fill this in with our
 * actual root page table pointer.
 */
	.p2align 2
GLOBL(ap_start_pt)
	.long 0x0
END(ap_start_pt)

GLOBL(ap_start_end)
END(ap_start_end)

	.section .text, "ax", @progbits
	.code64

/*
 * We are now in 64-bit mode with paging enabled. All that is left to do is set
 * up a stack and jump to SVA's startup code.
 */
ENTRY(ap_start_64)
	/*
	 * Load our segment selectors for long mode. Since we are in ring 0, we
	 * can just load them with 0 for now.
	 */
	xorl	%eax, %eax
	mov	%ax, %ss
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %fs
	mov	%ax, %gs

	/*
	 * Set up our stack.
	 */
	movabsq	ap_startup_stack, %rax
	movq	%rax, %rsp
#ifdef SVA_SPLIT_STACK
	movabsq	ap_startup_unprotected_stack, %rax
	movq	%rax, %r15
#endif

	/*
	 * The calling convention expects the stack to be at an offset of 8
	 * from 16-byte alignment upon entry to a function. Push a dummy value
	 * here to produce the correct alignment.
	 */
	movq	%rsp, %rbp
	movabsq	$0xdeaddeaddeaddead, %rax
	pushq	%rax

	jmp sva_init_secondary
END(ap_start_64)
