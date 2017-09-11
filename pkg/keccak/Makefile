PKG_NAME	:= keccak
PKG_URL		:= https://github.com/adrianghc/KeccakCodePackage
PKG_VERSION	:= 37b6305ba37f36c3f3de72524e181c83befe8eb4

.PHONY: all

all: git-download
	$(MAKE) hash-800-ARMv6M.a -C $(PKG_BUILDDIR)
	@cp $(PKG_BUILDDIR)/bin/hash-800-ARMv6M.a $(PKG_BUILDDIR)/../../../$(BOARD)/keccak.a

include $(RIOTBASE)/pkg/pkg.mk
