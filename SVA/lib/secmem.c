/*===- secmem.c - SVA Execution Engine  =------------------------------------===
 * 
 *                        Secure Virtual Architecture
 *
 * This file was developed by the LLVM research group and is distributed under
 * the University of Illinois Open Source License. See LICENSE.TXT for details.
 * 
 *===----------------------------------------------------------------------===
 *
 * This file implements the new secure memory feature of SVA.
 *
 *===----------------------------------------------------------------------===
 */

#include <string.h>

#include <sva/assert.h>
#include <sva/types.h>
#include <sva/config.h>
#include <sva/callbacks.h>
#include <sva/mmu.h>
#include <sva/mmu_intrinsics.h>
#include <sva/self_profile.h>
#include <sva/state.h>
#include <sva/util.h>

/* Size of frame cache queue */
#define FRAME_CACHE_SIZE 4096

/*
 * Maximum number of frames per allocation or deallocation,
 * if not randomly.
 */
#define MAX_FRAMES_PER_OP 32

/* Frame cache queue */
static uintptr_t frame_cache[FRAME_CACHE_SIZE];

/* Front and rear of frame cache queue */
static int frame_cache_st = 0;
static int frame_cache_ed = 0;

/* Lock for the frame cache */
static bool _frame_cache_lock = false;

/*
 * Internal frame cache queue operations, should not be called anywhere
 * else except in alloc_frame() and free_frame().
 */
static inline int frame_cache_used(void);
static inline int frame_cache_full(void);
static inline int frame_cache_empty(void);
static inline void frame_enqueue(uintptr_t paddr);
static inline uintptr_t frame_dequeue(void);
static inline uintptr_t get_frame_from_os(void);
static inline void return_frame_to_os(uintptr_t paddr);
static inline void fill_in_frames(void);
static inline void release_frames(void);

/*
 * Function: frame_cache_used()
 *
 * Description:
 *  Return the number of frames currently in the frame cache.
 */
static inline int
frame_cache_used(void) {
  return (frame_cache_ed - frame_cache_st + FRAME_CACHE_SIZE) % FRAME_CACHE_SIZE;
}

/*
 * Function: frame_cache_full()
 *
 * Description:
 *  Determine if the frame cache queue is full.
 */
static inline int
frame_cache_full(void) {
  return frame_cache_used() == FRAME_CACHE_SIZE - 1;
}

/*
 * Function: frame_cache_empty()
 *
 * Description:
 *  Determine if the frame cache queue is empty.
 */
static inline int
frame_cache_empty(void) {
  return frame_cache_used() == 0;
}

/*
 * Function: frame_enqueue()
 *
 * Description:
 *  Enqueue a frame into the frame cache queue.
 *
 * Input:
 *  paddr - The physical address of the frame to enqueue
 */
static inline void
frame_enqueue(uintptr_t paddr) {
  /* If our cache is full, release some frames */
  if (frame_cache_full()) {
    release_frames();
  }

  frame_cache[frame_cache_ed] = paddr;
  frame_cache_ed = (frame_cache_ed + 1) % FRAME_CACHE_SIZE;
}

/*
 * Function: frame_dequeue()
 *
 * Description:
 *  Dequeue a frame out of the frame cache queue.
 */
static inline uintptr_t
frame_dequeue(void) {
  uintptr_t paddr = 0;

  /* If we don't have any frames in cache, grab some */
  if (frame_cache_empty()) {
    fill_in_frames();
  }

  paddr = frame_cache[frame_cache_st];
  frame_cache[frame_cache_st] = 0;
  frame_cache_st = (frame_cache_st + 1) % FRAME_CACHE_SIZE;

  return paddr;
}

/*
 * Function: get_frame_from_os()
 *
 * Description:
 *  Use a kernel callback function to ask the operating system for a frame of
 *  physical memory, and verify that the OS has cleared all mappings that
 *  would allow it to access the frame.
 *
 *  This function will panic if it determines that the OS has *not* cleared
 *  all mappings to the frame. In this situation, the OS is "lying" to us,
 *  and is refusing to let us allocate secure memory.
 *
 *  The frame will be marked in SVA's frame_desc structure as having type
 *  PGT_SVA, so that SVA's MMU checks will preclude the OS from establishing
 *  any other mappings to it in the future.
 *
 *  Frames returned by this function are suitable for use as ghost memory
 *  backing or SVA internal memory. If they are to be used for ghost memory,
 *  their frame_desc type should be set to PGT_GHOST.
 *
 * Return value:
 *  The physical address of the frame acquired.
 */
static inline uintptr_t
get_frame_from_os(void) {
  /*
   * Ask the OS to give us a physical frame.
   *
   * If we are running with interrupts disabled (which we probably are, since
   * that's true of most if not all SVA code that could be calling this), we
   * must re-enable them before returning control to the OS.
   */
  uintptr_t prev_rflags;
  asm volatile (
      "pushfq\n"
      "popq %0\n"
      "sti\n" /* Enable interrupts if they aren't enabled already */
      : "=r" (prev_rflags)
      :: "memory" /* prevents compiler from reordering memory ops after STI */
      );

  /* Perform the callback to the OS. */
  uintptr_t paddr = provideSVAMemory(FRAME_SIZE);

  /* Re-disable interrupts if they were disabled before the callback. */
  if (!(prev_rflags & 0x00000200))
    asm volatile ("cli");

  /*
   * In provideSVAMemory(), the OS *should* have unmapped the frame from its
   * own direct map, and not have any other existing mappings to it. However,
   * we should not take its word for this, because it might have been
   * compromised.
   */

#ifdef FreeBSD
  /* Verify that the frame is unmapped in the kernel's direct map. */
  uintptr_t kerndmap_vaddr = (uintptr_t)getVirtual(paddr);
  pml4e_t* pml4e_ptr = get_pml4eVaddr(get_root_pagetable(), kerndmap_vaddr);
  if (isPresent(*pml4e_ptr)) {
    pdpte_t* pdpte_ptr = get_pdpteVaddr(*pml4e_ptr, kerndmap_vaddr);
    if (isPresent(*pdpte_ptr)) {
      pde_t* pde_ptr = get_pdeVaddr(*pdpte_ptr, kerndmap_vaddr);
      if (isPresent(*pde_ptr)) {
        pte_t* pte_ptr = get_pteVaddr(*pde_ptr, kerndmap_vaddr);
        if (isPresent(*pte_ptr)) {
          /* The frame is still present in the kernel's direct map. */
#if 0
          panic("SVA: OS gave us a frame for secure memory which it didn't "
              "remove from its direct map. The OS is lying to us and has "
              "been terminated with extreme prejudice. "
              "Frame physical address: 0x%lx\n", paddr);
#endif

          /*
           * Forcibly remove the frame from the kernel's direct map.
           *
           * TODO: Find out why this is sometimes necessary. In theory this
           * should never happen with a non-compromised kernel, and we should
           * therefore be able to just panic instead of trying to "fix" the
           * problem.
           *
           * Most of the time FreeBSD correctly removes its mapping, but
           * we've observed that it sometimes fails to do so under "heavier"
           * demand for ghost memory. (Specifically, this was observed when
           * running the lmbench test "open_close" with GHOSTING=1.)
           */
#if 0
          printf("SVA: OS gave us a frame for secure memory which it didn't "
              "remove from its direct map. SVA will remove it. "
              "Frame physical address: 0x%lx\n", paddr);
#endif
          __update_mapping(pte_ptr, ZERO_MAPPING);
        }
      }
    }
  }
#endif

  /*
   * Verify that there are no other mappings to the frame (except SVA's
   * direct map).
   *
   * We can use SVA's refcount for this because all non-direct mappings are
   * established through intrinsics that update it.
   */
  frame_desc_t * page = get_frame_desc(paddr);
  SVA_ASSERT(page != NULL,
    "SVA: FATAL: Kernel gave us a frame which doesn't exist\n");

  frame_morph(page, PGT_FREE);

  /*
   * Do a global TLB flush (including for EPT if SVA-VMX is active) to
   * ensure that there are no stale mappings to this page that the OS
   * neglected to flush.
   *
   * Ideally we'd prefer to selectively flush mappings from the TLB at the
   * time they are removed (e.g., in updateOrigPageData()), which would make
   * this unnecessary because we'd know the TLB is consistent at all times.
   * But SVA doesn't have a good way of knowing what virtual address(es)
   * correspond to a mapping that it's asked to remove, making this
   * impractical. Instead we leave it to the OS to flush the TLBs itself in
   * general, and only force a TLB flush when a failure by the OS to uphold
   * that responsibility could compromise SVA's security guarantees.
   *
   * There are two places in SVA's codebase this is the case:
   *  - In initDeclaredPage() (mmu.c), when we need to ensure that the OS
   *    *only* has access to a declared PTP through its entry in the kernel's
   *    DMAP (which SVA has made read-only).
   *
   *  - Here, in get_frame_from_os(), when we need to ensure that a
   *    frame the OS gave us for use as secure/ghost memory isn't accessible
   *    at all to the OS.
   */
  invltlb_all();
  if (getCPUState()->vmx_initialized) {
    /*
     * FIXME: there is a slight theoretical security hole here, in that the
     * vmx_initialized flag is per-CPU, and we rely on the system software to
     * call sva_initvmx() on each of those CPUs individually. In theory, the
     * system software could trick us by initializing VMX on some CPUs but
     * not others, and then taking advantage of the fact that
     * get_frame_from_os() operations on the CPUs where VMX is not initialized
     * will neglect to flush the EPT TLBs. We would need to think about this
     * a bit more to determine whether a feasible attack could actually arise
     * from this, but this comment stands for now out of an abundance of
     * caution.
     *
     * In practice, this shouldn't be a problem as the system software will
     * typically initialize VMX on all CPUs during boot. As SVA provides no
     * mechanism to *disable* VMX on a CPU once it's enabled, an attacker
     * could not exploit this thereafter. With security measures such as
     * secure boot in place we can generally assume that such boot-time
     * initialization will be performed as intended since most attack
     * surfaces for compromise of the system software are not exposed until
     * after (or later in) boot.
     */

    invept_allcontexts();
    invvpid_allcontexts();
  }

  /* Finally, return the physical address of the frame we have now vetted. */
  return paddr;
}

/*
 * Function: return_frame_to_os()
 *
 * Description:
 *  Return a frame acquired with get_frame_from_os().
 *
 *  The frame's page type in SVA's frame_desc structure will be returned to
 *  PGT_FREE, so that the OS is once again free to establish its own mappings
 *  to it.
 *
 * Argument:
 *  paddr - the physical address of the frame being returned.
 */
static inline void return_frame_to_os(uintptr_t paddr) {
  frame_desc_t* frame = get_frame_desc(paddr);
  SVA_ASSERT(frame != NULL,
    "SVA: Internal error: Returning non-existant frame 0x%lx to kernel\n",
    frame - frame_desc);
  frame_morph(frame, PGT_FREE);

  /*
   * Return the physical frame to the OS.
   *
   * If we are running with interrupts disabled (which we probably are, since
   * that's true of most if not all SVA code that could be calling this), we
   * must re-enable them before returning control to the OS.
   */
  uintptr_t prev_rflags;
  asm volatile (
      "pushfq\n"
      "popq %0\n"
      "sti\n" /* Enable interrupts if they aren't enabled already */
      : "=r" (prev_rflags)
      :: "memory" /* prevents compiler from reordering memory ops after STI */
      );

  /* Perform the callback to the OS. */
  releaseSVAMemory(paddr, FRAME_SIZE);

  /* Re-disable interrupts if they were disabled before the callback. */
  if (!(prev_rflags & 0x00000200))
    asm volatile ("cli");
}

/*
 * Function: fill_in_frames()
 *
 * Description:
 *  Allocate some number of frames and put them into the frame cache
 *  queue.
 */
static inline void
fill_in_frames(void) {
  int i, max_nframe, nframe;
  uintptr_t paddr;

  /*
   * Generate a suitable number not so big that triggers
   * release_frames() when calling frame_enqueue().
   */
  max_nframe = FRAME_CACHE_SIZE - 1 - frame_cache_used();
  if (vg_random) {
    /* A random number between 1 and current capacity of frame cache queue */
    nframe = sva_random() % max_nframe + 1;
  } else {
    /* Minimum of a constant and current capacity of frame cache queue */
    nframe = max_nframe < MAX_FRAMES_PER_OP ? max_nframe : MAX_FRAMES_PER_OP;
  }

  for (i = 0; i < nframe; ++i) {
    paddr = get_frame_from_os();
    frame_enqueue(paddr);
  }
}

/*
 * Function: release_frames()
 *
 * Description:
 *  Dequeue and free some number of frames in the frame cache queue.
 */
static inline void
release_frames(void) {
  int i, max_nframe, nframe;
  uintptr_t paddr;

  /*
   * Generate a suitable number not so big that triggers
   * fill_in_frames() when calling frame_dequeue().
   */
  max_nframe = frame_cache_used();
  if (vg_random) {
    /* A random number between 1 and current occupancy of frame cache queue */
    nframe = sva_random() % max_nframe + 1;
  } else {
    /* Minimum of a constant and current occupancy of frame cache queue */
    nframe = max_nframe < MAX_FRAMES_PER_OP ? max_nframe : MAX_FRAMES_PER_OP;
  }

  for (i = 0; i < nframe; ++i) {
    paddr = frame_dequeue();
    return_frame_to_os(paddr);
  }
}

static void frame_cache_lock(void) {
  while (__atomic_test_and_set(&_frame_cache_lock, __ATOMIC_RELAXED)) {
    __builtin_ia32_pause();
  }

  __atomic_thread_fence(__ATOMIC_ACQUIRE);
}

static void frame_cache_unlock(void) {
  __atomic_clear(&_frame_cache_lock, __ATOMIC_RELEASE);
}

/*
 * Function: alloc_frame()
 *
 * Description:
 *  The front end function for allocating a physical frame.
 *
 * Postconditions:
 *  1. The frame returned will have its type set to PGT_SVA in SVA's frame_desc
 *  structure, i.e., it is protected by the MMU checks to ensure that the OS
 *  cannot establish its own mapping to access the frame. Only SVA can add a
 *  mapping to it.
 *
 *  2. If the preconditions of free_frame() are always upheld, then this
 *  function is guaranteed to return a frame to which no mapping currently
 *  exists except in SVA's direct map.
 *
 * NOTE FOR SAFE USAGE:
 *  If the caller of this function is planning to use the frame as SVA
 *  internal memory, it should leave the type set to PGT_SVA. This allows SVA
 *  to protect it against unauthorized mappings.
 *
 *  If the frame is to be used for any other purpose, the caller is
 *  responsible for ensuring that any mappings to it (except SVA's DMAP) are
 *  cleared before calling free_frame(). If this is not done, the security of
 *  the system may be compromised if said mapping(s) continue to exist and
 *  the frame is later used for a sensitive purpose.
 *
 *  As an example, if a frame is allocated for use as ghost memory, its type
 *  will be changed to PGT_GHOST, which is also protected by the MMU checks.
 *  Before it calls free_frame(), ghostFree() will call unmapSecurePage(),
 *  which removes the ghost mapping and sets the type back to PGT_SVA.
 *
 * WARNING:
 *  This function will call back into the OS to request memory if SVA's frame
 *  cache doesn't currently contain a free frame. During that callback,
 *  interrupts are re-enabled and control is returned to the OS. Therefore,
 *  care should be taken to make sure that SVA code calls alloc_frame() only
 *  while the system is in a safe and consistent state for OS code to
 *  execute.
 */
uintptr_t
alloc_frame(void) {
  frame_cache_lock();
  uintptr_t paddr = frame_dequeue();
  frame_cache_unlock();
  return paddr;
}

/*
 * Function: free_frame()
 *
 * Description:
 *  The front end function for freeing a physical frame.
 *
 * Preconditions:
 *  1. The frame's type should be set to PGT_SVA in SVA's frame_desc structure.
 *
 *  2. No mappings to the frame should exist except in SVA's direct map.
 *     
 *     If the frame was only used as SVA internal memory, and no mappings
 *     were created, this condition is trivially upheld.
 *
 *     If the frame was used for any other purpose, it is the caller's
 *     responsibility to ensure that any non-SVA mappings either could never
 *     have been created (e.g., because the frame type was set to PGT_GHOST,
 *     which, like PGT_SVA, prevents the OS from mapping it), and/or that
 *     other mappings have been removed or confirmed to not exist.
 *
 *  If these preconditions are not always upheld, insecure mappings could
 *  slip through the cracks and compromise the security of the system when
 *  the frame is later reused.
 *
 * WARNING:
 *  This function will call back into the OS to return memory if SVA's frame
 *  cache becomes full as a result of returning this frame to it. During that
 *  callback, interrupts are re-enabled and control is returned to the OS.
 *  Therefore, care should be taken to make sure that SVA code calls
 *  alloc_frame() only while the system is in a safe and consistent state for
 *  OS code to execute.
 */
void
free_frame(uintptr_t paddr) {
  frame_cache_lock();
  frame_enqueue(paddr);
  frame_cache_unlock();
}

/*
 * Function: getNextSecureAddress()
 *
 * Description:
 *  Find the next available address in the secure virtual address space.
 *
 * Inputs:
 *  threadp - The thread for which to allocate more ghost memory.
 *  size    - The size of memory to allocate in bytes.
 */
static inline unsigned char *
getNextSecureAddress (struct SVAThread * threadp, uintptr_t size) {
  /* Start of virtual address space used for secure memory */
  unsigned char * secmemStartp = (unsigned char *)GHOSTMEMSTART;

  /* Secure memory address to return */
  unsigned char * secmemp = secmemStartp + threadp->secmemSize;

  /*
   * Advance the address by a single page frame and return the value before
   * increment.
   */
  threadp->secmemSize += size;
  return secmemp;
}

/*
 * Function: ghostMalloc()
 *
 * Description:
 *  Allocate ghost memory.
 */
unsigned char *
ghostMalloc (intptr_t size) {
  /* Virtual address assigned to secure memory by SVA */
  unsigned char *vaddrStart = 0;

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState *cpup = getCPUState();
  struct SVAThread *threadp = cpup->currentThread;

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Determine where this ghost memory will be allocated and update the size
   * of the ghost memory.
   */
  unsigned char *vaddr = vaddrStart = getNextSecureAddress(threadp, size);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   *
   * NOTE: calling alloc_frame() may (temporarily) re-enable interrupts and
   * return control to the system software via the provideSVAMemory()
   * callback. We must, therefore, be sure the system is in a safe and
   * consistent state at this time. We are safe here because we do not
   * actually map the ghost page into the virtual addres space until after
   * its physical frame has been successfully allocated.
   */
  for (intptr_t remaining = size; remaining > 0; remaining -= FRAME_SIZE) {
    uintptr_t frame_paddr;
    if ((frame_paddr = alloc_frame()) != 0) {
      /*
       * Map the memory into a part of the address space reserved for secure
       * memory.
       */
      pml4e_t pml4e = mapSecurePage((uintptr_t)vaddr, frame_paddr);

      /*
       * If this is the first piece of secure memory that we've allocated,
       * record the address of the top-level page table that maps in the secure
       * memory region.  The context switching intrinsics will want to know
       * where this entry is so that it can quickly enable and disable it on
       * context switches.
       */
      if (firstSecAlloc) {
        threadp->secmemPML4e = pml4e;
      }

      /*
       * Move to the next virtual address.
       */
      vaddr += PG_L1_SIZE;
    } else {
      panic("SVA: Kernel secure memory allocation failed!\n");
    }
  }

  /* Return a pointer to the allocated ghost memory */
  return vaddrStart;
}

/*
 * Function: allocSecureMemory()
 *
 * Description:
 *  Allocate secure memory.  Fetch it from the operating system kernel if
 *  necessary.
 *
 * Inputs:
 *  size - The amount of secure memory to allocate measured in bytes.
 *
 * Return value:
 *  A pointer to the first byte of the secure memory.
 */
unsigned char *
allocSecureMemory (void) {
  /*
   * Get the number of bytes to allocate.  This is stored in the %rdi register
   * of the interrupted program state.
   */
  struct CPUState *cpup = getCPUState();
  sva_icontext_t *icp = cpup->newCurrentIC;
  intptr_t size = icp->rdi;

  /*
   * Check that the size is positive.
   */
  if (size < 0)
    return 0;

  /*
   * If we have already allocated ghost memory, then merely extend the size of
   * of the ghost partition and let the ghost memory be demand paged into
   * memory.  Otherwise, allocate some ghost memory just to make adding the
   * demand-paged ghost memory easier.
   */
  unsigned char *vaddrStart = 0;
  struct SVAThread *threadp = cpup->currentThread;
  if (threadp->secmemSize && !pgdef) {
    /*
     * Pretend to allocate more ghost memory (but let demand paging actually
     * map it in.
     */
    vaddrStart = getNextSecureAddress(threadp, size);
  } else {
    /*
     * Call the ghost memory allocator to allocate some ghost memory.
     */
    vaddrStart = ghostMalloc(size);

    /*
     * Zero out the memory.
     */
    memset(vaddrStart, 0, size);
  }
  /*
   * Set the return value in the Interrupt Context to be a pointer to the
   * newly allocated memory.
   */
  icp->rax = (uintptr_t) vaddrStart;

  /*
   * Return the first address of the newly available ghost memory.
   */
  return vaddrStart;
}

/*
 * Function: ghostFree()
 *
 * Description:
 *  Free the physical frames backing ghost memory at the specified virtual
 *  address.  This function frees entire frames and returns the physical memory
 *  to the operating system kernel.
 *
 *  Note that this function may be called upon to unmap ghost memory from a
 *  thread *other* than the one currently running on the CPU.
 *
 * Inputs:
 *  threadp - A pointer to the SVA Thread for which we should release the frame
 *            of secure memory.
 *  p        - A pointer to the virtual address of the ghost memory to free.
 *  size     - The amount of ghost memory in bytes to free.
 *
 */
void ghostFree(struct SVAThread* threadp, void* p, size_t size) {
  /* Per-CPU data structure maintained by SVA */
  struct CPUState *cpup;

  /* Pointer to thread currently executing on the CPU */
  struct SVAThread *currentThread;

  /*
   * If the amount of memory to free is zero, do nothing.
   */
  if (size == 0) {
    return;
  }

  /*
   * Get a pointer to the thread currently running on the CPU.
   */
  cpup = getCPUState();
  currentThread = cpup->currentThread;

  /*
   * Get the PML4E entry for the Ghost Memory for the thread.
   */
  pml4e_t *secmemPML4Ep = &(threadp->secmemPML4e);

  /*
   * Verify that the memory is within the secure memory portion of the
   * address space.
   */
  if (is_ghost_addr((uintptr_t)p) && is_ghost_addr((uintptr_t)p + size)
      && size <= GHOSTMEMSIZE)
  {
    /*
     * Loop through each page of the ghost memory until all of the frames
     * have been returned to the operating system kernel.
     */
    for (char *ptr = p; ptr < ((char*)p + size); ptr += PG_L1_SIZE) {
      /*
       * Get the physical address before unmapping the page.  We do this
       * because unmapping the page may remove page table pages that are no
       * longer needed for mapping secure pages.
       */
      uintptr_t paddr;
      if (getPhysicalAddrFromPML4E(ptr, secmemPML4Ep, &paddr)) {
        
        /*
         * Unmap the memory from the secure memory virtual address space.
         */
        unmapSecurePage(threadp, (uintptr_t)ptr);

        /*
         * Release the memory to the operating system.  Note that we must first
         * get the physical address of the data page as that is what the OS is
         * expecting.
         *
         * TODO:
         *  This code works around a limitation in the releaseSVAMemory()
         *  implementation in which it only releases one page at a time to the
         *  OS.
         *
         * NOTE: calling free_frame() may (temporarily) re-enable interrupts and
         * return control to the system software via the releaseSVAMemory()
         * callback. We must, therefore, be sure the system is in a safe and
         * consistent state at this time. We are safe here because we have
         * already unmapped the ghost page from the virtual address space
         * and cleared its contents before returning control to the OS.
         * Additionally, there is no further bookkeeping performed to keep
         * SVA's metadata in order between freeing the frame and returning
         * from this function (and from its caller, freeSecureMemory()).
         */
        /*
         * count == 1 means mapped only in SVA's DMAP, i.e. no more ghost
         * mappings point to this frame. Zero the frame before returning it
         * to the frame cache (and thence to the OS).
         */
        if (get_frame_desc(paddr)->type_count == 0) {
          /*
           * Zero out the contents of the ghost memory.
           */
          if (threadp == currentThread) {
            unsigned char *dmapAddr = getVirtualSVADMAP(paddr);
            memset(dmapAddr, 0, PG_L1_SIZE);
          }
          free_frame(paddr);
        }
      }
    }
  }

  return;
}

/*
 * Function: freeSecureMemory()
 *
 * Description:
 *  Free a single page of secure memory.
 */
void
freeSecureMemory (void) {
  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  sva_icontext_t * icp = getCPUState()->newCurrentIC;

  /*
   * Get the pointer address and size out of the interrupt context.
   */
  unsigned char * p = (unsigned char *)(icp->rdi);
  uintptr_t size = icp->rsi;

  /* Free the ghost memory */
  struct CPUState * cpup = getCPUState();
  ghostFree (cpup->currentThread, p, size);

  return;
}

void
sva_ghost_fault (uintptr_t vaddr, unsigned long code) {
  SVA_PROF_ENTER();

  kernel_to_usersva_pcid();

  /*
   * Disable interrupts.
   */
  uintptr_t rflags = sva_enter_critical();

  /*
   * Get the current interrupt context; the arguments will be in it.
   */
  struct CPUState *cpup = getCPUState();
  struct SVAThread *threadp = cpup->currentThread;

  /* copy-on-write page fault */
  if ((code & PGEX_P) && (code & PGEX_W)) {
    /* The address of the PML4e page table */
    pml4e_t *pml4e = get_pml4eVaddr(get_root_pagetable(), vaddr);
    if (!isPresent(*pml4e))
      panic("sva_ghost_fault: cow pgfault pml4e %p does not exist\n", pml4e);

    pdpte_t *pdpte = get_pdpteVaddr(*pml4e, vaddr);
    if (!isPresent(*pdpte))
      panic("sva_ghost_fault: cow pgfault pdpte %p does not exist\n", pdpte);

    pde_t *pde = get_pdeVaddr(*pdpte, vaddr);
    if (!isPresent(*pde))
      panic("sva_ghost_fault: cow pgfault pde %p does not exist\n", pde);

    pte_t *pte = get_pteVaddr(*pde, vaddr);
    uintptr_t paddr = PG_L1_FRAME(*pte);

    frame_desc_t *pgDesc_old = get_frame_desc(paddr);
    SVA_ASSERT(pgDesc_old != NULL,
      "SVA: FATAL: Ghost memory mapped to non-existant frame\n");
    if (pgDesc_old->type != PGT_GHOST)
      panic("SVA: sva_ghost_fault: vaddr = 0x%lx paddr = 0x%lx "
          "is not a ghost memory page!\n", vaddr, paddr);

    /*
     * If only one process maps this page, directly grant this process write
     * permission.  Otherwise, perform a copy-on-write.
     */
    if (pgDesc_old->type_count == 1) {
      *pte |= PG_W;
    } else {
      /*
       * Perform a copy-on-write.
       */

      void *vaddr_old = getVirtualSVADMAP(paddr);

      /*
       * Get a frame from the frame cache for the new process's copy of the
       * page, and check that it's suitable for use as ghost memory.
       *
       * NOTE: calling alloc_frame() may (temporarily) re-enable interrupts
       * and return control to the system software via the provideSVAMemory()
       * callback. We must, therefore, be sure the system is in a safe and
       * consistent state at this time. We are safe here because we do not
       * actually change the page table entry to use the new copy until its
       * physical frame has been successfully allocated.
       */
      uintptr_t paddr_new = alloc_frame();
      void *vaddr_new = getVirtualSVADMAP(paddr_new);
      frame_desc_t *pgDesc_new = get_frame_desc(paddr_new);
      SVA_ASSERT(pgDesc_new != NULL,
        "SVA: FATAL: New ghost memory allocation is a non-existant frame\n");

      /*
       * Copy the page contents to the new process's copy.
       */
      memcpy(vaddr_new, vaddr_old, PG_L1_SIZE);
      *pte = PG_ENTRY_FRAME(paddr_new) | PG_P | PG_W | PG_U;
      /* Update the TLB to reflect the change. */
      invlpg(vaddr);

      /*
       * Set the frame type and increment the refcount for the new process's
       * copy. This will also make sure the kernel doesn't still have any
       * mappings to this frame.
       */
      frame_morph(pgDesc_new, PGT_GHOST);
      frame_take(pgDesc_new, PGT_GHOST);

      /*
       * Decrement the refcount for the old copy to reflect that it is no
       * longer being shared by the process that got the new copy.
       */
      frame_drop(pgDesc_old, PGT_GHOST);
    }
    return;
  }

  /*
   * Determine if this is the first secure memory allocation.
   */
  unsigned char firstSecAlloc = (threadp->secmemSize == 0);

  /*
   * Get a page of memory from the operating system.  Note that the OS provides
   * the physical address of the allocated memory.
   *
   * NOTE: calling alloc_frame() may (temporarily) re-enable interrupts and
   * return control to the system software via the provideSVAMemory()
   * callback. We must, therefore, be sure the system is in a safe and
   * consistent state at this time. We are safe here because we do not
   * actually map the ghost page into the virtual addres space until after
   * its physical frame has been successfully allocated.
   */
  uintptr_t frame_paddr;
  if ((frame_paddr = alloc_frame()) != 0) {
    /*
     * Map the memory into a part of the address space reserved for secure
     * memory.
     */
    pml4e_t pml4e = mapSecurePage((uintptr_t) vaddr, frame_paddr);

    /*
     * If this is the first piece of secure memory that we've allocated,
     * record the address of the top-level page table that maps in the secure
     * memory region.  The context switching intrinsics will want to know
     * where this entry is so that it can quickly enable and disable it on
     * context switches.
     */
    if (firstSecAlloc) {
      threadp->secmemPML4e = pml4e;
    }
  } else {
    panic("SVA: Kernel secure memory allocation failed!\n");
  }

  /*
   * Zero out the ghost memory contents.
   */
  memset((void*)vaddr, 0, PG_L1_SIZE);

  /* Re-enable interrupts if necessary */
  sva_exit_critical(rflags);
  usersva_to_kernel_pcid();

  SVA_PROF_EXIT(ghost_fault);
}

bool trap_pfault_ghost(unsigned __attribute__((unused)) trapno, void* addr) {
  if (is_ghost_addr((uintptr_t)addr)) {
    sva_icontext_t* p = getCPUState()->newCurrentIC;
    uintptr_t vaddr = PG_L1_DOWN(addr);
    sva_ghost_fault(vaddr, p->code);
    return true;
  } else {
    return false;
  }
}

