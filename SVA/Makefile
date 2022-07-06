#
# Include make.conf to configure the locations of the compiler
#
include ../make.conf

all:
	cd lib; $(MAKE)

INSTALL-lib := $(INSTALL) --mode=644 -t "$(DISTDIR)/lib/"
INSTALL-h := $(INSTALL) --mode=644 -t "$(DISTDIR)/include/sva/"
install: all
	$(INSTALL-lib) "lib/libsva.a"
	$(INSTALL-h) "include/sva/asmconfig.h"
	$(INSTALL-h) "include/sva/asm_const.h"
	$(INSTALL-h) "include/sva/callbacks.h"
	$(INSTALL-h) "include/sva/fpu_types.h"
	$(INSTALL-h) "include/sva/init.h"
	$(INSTALL-h) "include/sva/interrupt.h"
	$(INSTALL-h) "include/sva/invoke.h"
	$(INSTALL-h) "include/sva/mmu_intrinsics.h"
	$(INSTALL-h) "include/sva/mmu_types.h"
	$(INSTALL-h) "include/sva/secmem.h"
	$(INSTALL-h) "include/sva/state.h"
	$(INSTALL-h) "include/sva/types.h"
	$(INSTALL-h) "include/sva/vmx_intrinsics.h"

clean:
	cd lib; $(MAKE) clean

.PHONY: all install clean
