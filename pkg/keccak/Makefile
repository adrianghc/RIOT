PKG_NAME    := keccak
PKG_URL     := https://github.com/gvanas/KeccakCodePackage
PKG_VERSION := 3f441eb7090771a7611682a63fa9caa1dd85e387

ifeq ($(CPU),native)
	CPU_ARCH_NAME := Native
	CPU_ARCHIVE_NAME := Native
else
ifeq ($(CPU_ARCH),cortex-m0)
	CPU_ARCH_NAME := CortexM0
	CPU_ARCHIVE_NAME := ARMv6M
else
ifeq ($(CPU_ARCH),cortex-m0plus)
	CPU_ARCH_NAME := CortexM0Plus
	CPU_ARCHIVE_NAME := ARMv6M
else
ifeq ($(CPU_ARCH),cortex-m3)
	CPU_ARCH_NAME := CortexM3
	CPU_ARCHIVE_NAME := ARMv7M
else
ifeq ($(CPU_ARCH),$(filter $(CPU_ARCH), cortex-m4 cortex-m4f))
	CPU_ARCH_NAME := CortexM4
	CPU_ARCHIVE_NAME := ARMv7M
endif
endif
endif
endif
endif

.PHONY: all

all: git-download
	@cp -r $(RIOTBASE)/pkg/keccak/contrib/Modes $(PKG_BUILDDIR)
	@cp $(RIOTBASE)/pkg/keccak/contrib/Build/CompilerFlags$(CPU_ARCH_NAME).build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash$(CPU_ARCHIVE_NAME).a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash$(CPU_ARCHIVE_NAME).a $(BINDIR)/keccak.a

include $(RIOTBASE)/pkg/pkg.mk
