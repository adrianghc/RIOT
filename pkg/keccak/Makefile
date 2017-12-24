PKG_NAME    := keccak
PKG_URL     := https://github.com/gvanas/KeccakCodePackage
PKG_VERSION := bc592d1780a6b3204c26c6f872552ace8fc6fd65

ifeq ($(CPU),native)
	CPU_ARCHIVE_NAME := Native
else
ifeq ($(CPU_ARCH),$(filter $(CPU_ARCH), cortex-m0 cortex-m0plus))
	CPU_ARCHIVE_NAME := ARMv6M
else
ifeq ($(CPU_ARCH),$(filter $(CPU_ARCH), cortex-m3 cortex-m4 cortex-m4f cortex-m7 cortex-m7f))
	CPU_ARCHIVE_NAME := ARMv7M
endif
endif
endif

.PHONY: all

all:
	@cp -r $(RIOTBASE)/pkg/keccak/contrib/Modes $(PKG_BUILDDIR)
	$(MAKE) KeccakHash$(CPU_ARCHIVE_NAME).a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash$(CPU_ARCHIVE_NAME).a $(BINDIR)/keccak.a

include $(RIOTBASE)/pkg/pkg.mk
