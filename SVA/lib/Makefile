#
# Makefile
#

#
# Include make.conf to configure the locations of the compiler
#
include ../../make.conf

CPPFLAGS += -I../include -include sva/compiler.h

CFLAGS += -O2 -fno-strict-aliasing -fno-omit-frame-pointer -fno-exceptions -ffreestanding -fpic -fno-common -sva -fno-sva-sfi
CFLAGS += -msoft-float -mno-mmx -mno-sse -mno-avx -mno-aes -mcmodel=medium -mno-red-zone

ASFLAGS += -ffreestanding -fpic -fno-common -sva
ASFLAGS += -msoft-float -mno-mmx -mno-sse -mno-avx -mno-aes -mcmodel=kernel -mno-red-zone


OFILES = init.o secmem.o handlers.o mmu.o mmu_init.o interrupt.o state.o \
         frame_meta.o debug.o stateasm.o invoke.o invokeasm.o checks.o keys.o \
         thread_stack.o profile.o vmx.o vmx_ept.o

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

%.o: %.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c "$<" -o "$@"

clean:
	rm -f *.a *.o *.i

