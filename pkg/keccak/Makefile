PKG_NAME	:= keccak
PKG_URL		:= https://github.com/adrianghc/KeccakCodePackage
PKG_VERSION	:= b908cbb392b601179d31659a628def6ad20fc8c1

.PHONY: all

all: git-download
ifeq ($(CPU),native)
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsNative.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800Native.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800Native.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
else
ifeq ($(CPU_ARCH),$(filter $(CPU_ARCH), cortex-m0 cortex-m0plus))
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsARMv6M.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800ARMv6M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800ARMv6M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
endif
endif

include $(RIOTBASE)/pkg/pkg.mk
