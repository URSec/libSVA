#
# Makefile
#

#
# Include make.conf to configure the locations of the compiler
#
include ../../make.conf

CPPFLAGS += -I../include
CFLAGS += -O2 -fno-strict-aliasing -fno-omit-frame-pointer -mno-aes -mno-avx -mcmodel=kernel -mno-red-zone -mno-mmx -msoft-float  -fno-asynchronous-unwind-tables -ffreestanding -sva -fno-sva-sfi -no-integrated-as

OFILES = init.o secmem.o handlers.o mmu.o interrupt.o state.o debug.o \
         stateasm.o invoke.o invokeasm.o checks.o keys.o thread_stack.o \
         profile.o vmx.o vmx_ept.o

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

clean:
	rm -f *.a *.o *.i

