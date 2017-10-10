PKG_NAME	:= keccak
PKG_URL		:= https://github.com/adrianghc/KeccakCodePackage
PKG_VERSION	:= 84fd5833efc8e5d0d4e1edaa2595dd2f6f160c13

.PHONY: all

all: git-download
ifeq ($(CPU),native)
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsNative.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800Native.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800Native.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
else
ifeq ($(CPU_ARCH),cortex-m0)
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsCortexM0.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800ARMv6M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800ARMv6M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
else
ifeq ($(CPU_ARCH),cortex-m0plus)
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsCortexM0Plus.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800ARMv6M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800ARMv6M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
else
ifeq ($(CPU_ARCH),cortex-m3)
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsCortexM3.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800ARMv7M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800ARMv7M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
else
ifeq ($(CPU_ARCH),$(filter $(CPU_ARCH), cortex-m4 cortex-m4f))
	@cp $(PKG_BUILDDIR)/Build/CompilerFlagsCortexM4.build $(PKG_BUILDDIR)/CompilerFlags.build
	$(MAKE) KeccakHash800ARMv7M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/KeccakHash800ARMv7M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a
endif
endif
endif
endif
endif

include $(RIOTBASE)/pkg/pkg.mk
