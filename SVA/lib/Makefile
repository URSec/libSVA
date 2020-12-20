#
# Makefile
#

#
# Include make.conf to configure the locations of the compiler
#
include ../../make.conf

WARN_FLAGS = -Wall -Wextra -Werror

CPPFLAGS += -I../include -include sva/compiler.h
CPPFLAGS += $(WARN_FLAGS)

OPT_FLAGS += -O2 -fno-strict-aliasing -fno-omit-frame-pointer

TARGET_FLAGS += -sva -fno-sva-sfi					\
		-ffreestanding -fno-exceptions -fpic -fno-common	\
		-msoft-float -mno-mmx -mno-sse -mno-avx -mno-aes	\
		-mno-red-zone -mcmodel=medium

CFLAGS += -std=gnu11
CFLAGS += $(OPT_FLAGS)
CFLAGS += $(TARGET_FLAGS)

ASFLAGS += $(TARGET_FLAGS)

OFILES = init.o secmem.o handlers.o fpu.o mmu.o mmu_init.o interrupt.o state.o \
         frame_meta.o debug.o stateasm.o invoke.o invokeasm.o checks.o keys.o \
         thread_stack.o profile.o uaccess.o vmx.o vmx_ept.o ap_start.o

all: libsva.a

include $(patsubst %,%.d,$(OFILES))

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

%.o.d: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MM -MT "$@ $(patsubst %.d,%,$@)" "$<" -MF "$@"

%.o.d: %.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) -MM -MT "$@ $(patsubst %.d,%,$@)" "$<" -MF "$@"

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

%.o: %.S
	$(CC) $(CPPFLAGS) $(ASFLAGS) -c "$<" -o "$@"

clean:
	rm -f *.a *.o *.i *.d

