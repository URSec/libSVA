//===- SFI.cpp - Instrument loads/stores for Software Fault Isolation ----- --//
// 
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
// 
//===----------------------------------------------------------------------===//
//
// This pass instruments loads and stores to prevent them from accessing
// protected regions of the virtual address space.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "sva"

#include "llvm/ADT/Statistic.h"
#include "llvm/Attributes.h"
#include "llvm/Constants.h"
#include "llvm/InlineAsm.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/Target/TargetData.h"

// Pass Statistics
namespace {
  STATISTIC (LSChecks, "Load/Store Instrumentation Added");
}

/* Command line option for enabling checks on loads */
static llvm::cl::opt<bool>
DoLoadChecks("enable-sfi-loadchecks",
             llvm::cl::desc("Add SFI checks to loads"),
             llvm::cl::init(false));

/* Command line option for enabling SVA Memory checks */
static llvm::cl::opt<bool>
DoSVAChecks("enable-sfi-svachecks",
            llvm::cl::desc("Add special SFI checks for SVA Memory"),
            llvm::cl::init(false));

/* Command line option for enabling SVA Memory checks */
static llvm::cl::opt<bool>
UseMPX("enable-mpx-sfi",
            llvm::cl::desc("Use Intel MPX extensions for SFI"),
            llvm::cl::init(false));

#if 0
/* Mask to determine if we use the original value or the masked value */
static const uintptr_t checkMask = 0xffffff0000000000u;
#else
/* Mask to determine if we use the original value or the masked value */
static const uintptr_t checkMask = 0x00000000ffffff00;
#endif

/* Mask to set proper lower-order bits */
static const uintptr_t setMask   = 0x0000008000000000u;

// Location of secure memory
static uintptr_t startGhostMemory = 0xffffff0000000000u;

namespace llvm {
  //
  // Pass: SFI
  //
  // Description:
  //  This pass instruments loads and stores for software fault isolation.
  //
  struct SFI : public FunctionPass, InstVisitor<SFI>{
   public:
     static char ID;
     SFI() : FunctionPass(ID) {}
      virtual bool runOnFunction (Function & F);
      const char *getPassName() const {
        return "SFI Instrumentation";
      }
     
      virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        // Prerequisite passes
        AU.addRequired<TargetData>();

        // Preserve the CFG
        AU.setPreservesCFG();
        return;
      }

     // Initialization method
     bool doInitialization (Module & M);

     // Visitor methods
     void visitLoadInst  (LoadInst  & LI);
     void visitStoreInst (StoreInst & SI);
     void visitAtomicCmpXchgInst (AtomicCmpXchgInst &I);
     void visitAtomicRMWInst (AtomicRMWInst &I);
     void visitCallInst (CallInst & CI);
     void visitMemCpyInst (MemCpyInst & MCI);

   private:
     bool isTriviallySafe (Value * Ptr, Type * Type);
     Value * addBitMasking (Value * Pointer, Instruction & I);
     void instrumentMemcpy(Value * D, Value * S, Value * L, Instruction * I);
  };
}

using namespace llvm;

namespace llvm {

char SFI::ID = 0;

static RegisterPass<SFI>
X ("sfi", "Insert SFI load/store instrumentation");

//
// Method: isTriviallySafe()
//
// Description:
//  This method determines if a memory access of the specified type is safe
//  (and therefore does not need a run-time check).
//
// Inputs:
//  Ptr     - The pointer value that is being checked.
//  MemType - The type of the memory access.
//
// Return value:
//  true  - The memory access is safe and needs no run-time check.
//  false - The memory access may be unsafe and needs a run-time check.
//
// FIXME:
//  Performing this check here really breaks the separation of concerns design
//  that we try to follow; this should really be implemented as a separate
//  optimization pass.  That said, it is quicker to implement it here.
//
bool
SFI::isTriviallySafe (Value * Ptr, Type * MemType) {
  //
  // Attempt to see if this is a stack or global allocation.  If so, get the
  // allocated type.
  //
  Type * AllocatedType = 0;
#if 0
  if (AllocaInst * AI = dyn_cast<AllocaInst>(Ptr->stripPointerCasts())) {
    if (!(AI->isArrayAllocation())) {
      AllocatedType = AI->getAllocatedType();
    }
  }
#endif

  if (GlobalVariable * GV=dyn_cast<GlobalVariable>(Ptr->stripPointerCasts())) {
    AllocatedType = GV->getType()->getElementType();
  }

  //
  // If this is not a stack or global object, it is unsafe (it might be
  // deallocated, for example).
  //
  if (!AllocatedType)
    return false;

  //
  // If the types are the same, then the access is safe.
  //
  if (AllocatedType == MemType)
    return true;

  //
  // Otherwise, see if the allocated type is larger than the accessed type.
  //
  TargetData & TD = getAnalysis<TargetData>();
  uint64_t AllocTypeSize = TD.getTypeAllocSize(AllocatedType);
  uint64_t MemTypeSize   = TD.getTypeStoreSize(MemType);
  return (AllocTypeSize >= MemTypeSize);
}

//
// Method: doInitialization()
//
// Description:
//  This method is called by the PassManager to permit this pass to perform one
//  time global initialization.  In this particular pass, we will add a
//  declaration for a utility function.
//
bool
SFI::doInitialization (Module & M) {
#if 0
  M.getOrInsertFunction ("sva_checkptr",
                         Type::getVoidTy (M.getContext()),
                         Type::getInt64Ty (M.getContext()),
                         0);
#endif

  //
  // Add a function for checking memcpy().
  //
  M.getOrInsertFunction ("sva_check_buffer",
                         Type::getVoidTy (M.getContext()),
                         Type::getInt64Ty (M.getContext()),
                         Type::getInt64Ty (M.getContext()),
                         0);
  return true;
}

//
// Method: addBitMasking()
//
// Description:
//  Add code before the specified instruction to perform the appropriate
//  bit-masking of the specified pointer.
//
Value *
SFI::addBitMasking (Value * Pointer, Instruction & I) {
  // Object which provides size of data types on target machine
  TargetData & TD = getAnalysis<TargetData>();

  // Integer type that is the size of a pointer on the target machine
  Type * IntPtrTy = TD.getIntPtrType(I.getContext());

  if (UseMPX) {
    //
    // Get a reference to the context to the LLVM module which this code is
    // transforming.
    //
    LLVMContext & Context = I.getContext();

    //
    // Create a pointer value that is the pointer minus the start of the
    // secure memory.
    //
    unsigned ptrSize = TD.getPointerSize();
    Constant * adjSize = ConstantInt::get (IntPtrTy,
                                           startGhostMemory,
                                           false);
    Value * IntPtr = new PtrToIntInst (Pointer,
                                       IntPtrTy,
                                       Pointer->getName(),
                                       &I);
    Value * AdjustPtr = BinaryOperator::Create (Instruction::Sub,
                                                IntPtr,
                                                adjSize,
                                                "adjSize",
                                                &I);
    AdjustPtr = new IntToPtrInst (AdjustPtr,
                                  Pointer->getType(),
                                  Pointer->getName(),
                                  &I);

    //
    // Create a function type for the inline assembly instruction.
    //
    FunctionType * CheckType;
    CheckType = FunctionType::get(Type::getVoidTy(Context),
                                  Pointer->getType(),
                                  false);

    //
    // Create an inline assembly "value" that will perform the bounds check.
    //
    Value * LowerBoundsCheck = InlineAsm::get (CheckType,
                                               "bndcl $0, %bnd0\n",
                                               "r,~{dirflag},~{fpsr},~{flags}",
                                               true);

    //
    // Create the lower bounds check.  Do this before calculating the address
    // for the upper bounds check; this might reduce register pressure.
    //
    CallInst::Create (LowerBoundsCheck, AdjustPtr, "", &I);
    return Pointer;
  } else {
    //
    // Create the integer values used for bit-masking.
    //
    Value * CheckMask = ConstantInt::get (IntPtrTy, checkMask);
    Value * SetMask   = ConstantInt::get (IntPtrTy, setMask);
    Value * Zero      = ConstantInt::get (IntPtrTy, 0u);
    Value * ThirtyTwo = ConstantInt::get (IntPtrTy, 32u);
    Value * svaLow    = ConstantInt::get (IntPtrTy, 0xffffffff819ef000u);
    Value * svaHigh   = ConstantInt::get (IntPtrTy, 0xffffffff89b96060u);

    //
    // Convert the pointer into an integer and then shift the higher order bits
    // into the lower-half of the integer.  Bit-masking operations can use
    // constant operands, reducing register pressure, if the operands are 32-bits
    // or smaller.
    //
    Value * CastedPointer = new PtrToIntInst (Pointer, IntPtrTy, "ptr", &I);
    Value * PtrHighBits = BinaryOperator::Create (Instruction::LShr,
                                                  CastedPointer,
                                                  ThirtyTwo,
                                                  "highbits",
                                                  &I);
                                                      
    //
    // Create an instruction to mask off the proper bits to see if the pointer
    // is within the secure memory range.
    //
    Value * CheckMasked = BinaryOperator::Create (Instruction::And,
                                                  PtrHighBits,
                                                  CheckMask,
                                                  "checkMask",
                                                  &I);

    //
    // Compare the masked pointer to the mask.  If they're the same, we need to
    // set that bit.
    //
    Value * Cmp = new ICmpInst (&I,
                                CmpInst::ICMP_EQ,
                                CheckMasked,
                                CheckMask,
                                "cmp");

    //
    // Create the select instruction that, at run-time, will determine if we use
    // the bit-masked pointer or the original pointer value.
    //
    Value * MaskValue = SelectInst::Create (Cmp, SetMask, Zero, "ptr", &I);

    //
    // Create instructions that create a version of the pointer with the proper
    // bit set.
    //
    Value * Masked = BinaryOperator::Create (Instruction::Or,
                                             CastedPointer,
                                             MaskValue,
                                             "setMask",
                                             &I);

    //
    // Insert a special check to protect SVA memory.  Note that this is a hack
    // that is used because the SVA memory isn't positioned after Ghost Memory
    // like it should be as described in the Virtual Ghost and KCoFI papers.
    //
    Value * Final = Masked;
    if (DoSVAChecks) {
      //
      // Compare against the first and last SVA addresses.  
      //
      Value * svaLCmp = new ICmpInst (&I,
                                  CmpInst::ICMP_ULE,
                                  svaLow,
                                  Masked,
                                  "svacmp");
      Value * svaHCmp = new ICmpInst (&I,
                                  CmpInst::ICMP_ULE,
                                  Masked,
                                  svaHigh,
                                  "svacmp");
      Value * InSVA = BinaryOperator::Create (Instruction::And,
                                               svaLCmp,
                                               svaHCmp,
                                               "inSVA",
                                               &I);

      //
      // Create a value of the pointer that is zero.
      //
      Value * mkZero = BinaryOperator::Create (Instruction::Xor,
                                               Masked,
                                               Masked,
                                               "mkZero",
                                               &I);

      //
      // Select the correct value based on whether the pointer is in SVA memory.
      //
      Value * Final = SelectInst::Create (InSVA, mkZero, Masked, "fptr", &I);
    }

    return (new IntToPtrInst (Final, Pointer->getType(), "masked", &I));
  }
}

void
SFI::instrumentMemcpy (Value * Dst, Value * Src, Value * Len, Instruction * I) {
  return;
  //
  // Cast the pointers to integers.  Only cast the source pointer if we're
  // adding SFI checks to loads.
  //
  TargetData & TD = getAnalysis<TargetData>();
  Type * IntPtrTy = TD.getIntPtrType(I->getContext());
  Value * DstInt = new PtrToIntInst (Dst, IntPtrTy, "dst", I);
  Value * SrcInt = 0;
  if (DoLoadChecks) {
    SrcInt = new PtrToIntInst (Src, IntPtrTy, "src", I);
  }

  //
  // Setup the function arguments.
  //
  Value * Args[2];
  Args[0] = DstInt;
  Args[1] = Len;

  //
  // Get the function.
  //
  Module * M = I->getParent()->getParent()->getParent();
  Function * CheckF = cast<Function>(M->getFunction ("sva_check_buffer"));
  assert (CheckF && "sva_check_memcpy not found!\n");

  //
  // Create a call to the checking function.
  //
  CallInst::Create (CheckF, Args, "", I);

  //
  // Create another call to check the source if SFI checks on loads have been
  // enabled.
  //
  if (DoLoadChecks) {
    Value * SrcArgs[2];
    SrcArgs[0] = SrcInt;
    SrcArgs[1] = Len;
    CallInst::Create (CheckF, SrcArgs, "", I);
  }

  return;
}

void
SFI::visitMemCpyInst (MemCpyInst & MCI) {
  //
  // Fetch the arguments to the memcpy.
  //
  Value * Dst = MCI.getDest();
  Value * Src = MCI.getSource();
  Value * Len = MCI.getLength();

  instrumentMemcpy (Dst, Src, Len, &MCI);
  return;
}

//
// Method: visitCallInst()
//
// Description:
//  Place a run-time check on certain intrinsic functions.
//
void
SFI::visitCallInst (CallInst & CI) {
  if (MemCpyInst * MCI = dyn_cast<MemCpyInst>(&CI)) {
    visitMemCpyInst (*MCI);
  }

  if (Function * F = CI.getCalledFunction()) {
    if (F->hasName() && F->getName().equals("memcpy")) {
      CallSite CS(&CI);
      instrumentMemcpy (CS.getArgument(0),
                        CS.getArgument(1),
                        CS.getArgument(2),
                        &CI);
    }
  }
  return;
}

//
// Method: visitLoadInst()
//
// Description:
//  Place a run-time check on a load instruction.
//
void
SFI::visitLoadInst (LoadInst & LI) {
  //
  // Add a check to the load if the option for instrumenting loads is enabled.
  //
  if (DoLoadChecks) {
    //
    // Don't instrument trivially safe memory accesses.
    //
    Value * Pointer = LI.getPointerOperand();
    if (isTriviallySafe (Pointer, LI.getType())) {
      return;
    }

    //
    // Add the bit masking for the pointer.
    //
    Value * newPtr = addBitMasking (Pointer, LI);

    //
    // Update the operand of the store so that it uses the bit-masked pointer.
    //
    LI.setOperand (0, newPtr);

    //
    // Update the statistics.
    //
    ++LSChecks;
  }
  return;
}

//
// Method: visitStoreInst()
//
// Description:
//  Place a run-time check on a store instruction.
//
void
SFI::visitStoreInst (StoreInst & SI) {
  //
  // Don't instrument trivially safe memory accesses.
  //
  Value * Pointer = SI.getPointerOperand();
  if (isTriviallySafe (Pointer, SI.getValueOperand()->getType())) {
    return;
  }

  //
  // Add the bit masking for the pointer.
  //
  Value * newPtr = addBitMasking (SI.getPointerOperand(), SI);

  //
  // Update the operand of the store so that it uses the bit-masked pointer.
  //
  SI.setOperand (1, newPtr);

  //
  // Update the statistics.
  //
  ++LSChecks;
  return;
}

void
SFI::visitAtomicCmpXchgInst (AtomicCmpXchgInst & AI) {
  //
  // Don't instrument trivially safe memory accesses.
  //
  Value * Pointer = AI.getPointerOperand();
  if (isTriviallySafe (Pointer, AI.getNewValOperand()->getType())) {
    return;
  }

  //
  // Add the bit masking for the pointer.
  //
  Value * newPtr = addBitMasking (Pointer, AI);

  //
  // Update the operand of the store so that it uses the bit-masked pointer.
  //
  AI.setOperand (0, newPtr);

  //
  // Update the statistics.
  //
  ++LSChecks;
  return;
}

void
SFI::visitAtomicRMWInst (AtomicRMWInst & AI) {
  //
  // Don't instrument trivially safe memory accesses.
  //
  Value * Pointer = AI.getPointerOperand();
  if (isTriviallySafe (Pointer, AI.getValOperand()->getType())) {
    return;
  }

  //
  // Add the bit masking for the pointer.
  //
  Value * newPtr = addBitMasking (Pointer, AI);

  //
  // Update the operand of the store so that it uses the bit-masked pointer.
  //
  AI.setOperand (0, newPtr);

  //
  // Update the statistics.
  //
  ++LSChecks;
  return;
}

bool
SFI::runOnFunction (Function & F) {
  //
  // Visit all of the instructions in the function.
  //
  visit (F);
  return true;
}

}

namespace llvm {
  FunctionPass * createSFIPass (void) {
    return new SFI();
  }
}
