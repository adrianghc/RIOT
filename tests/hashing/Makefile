APPLICATION = hashing

RIOTBASE ?= $(CURDIR)/../..
BOARD ?= native

USEMODULE += xtimer
USEMODULE += random
USEMODULE += hashes
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEPKG += keccak

CFLAGS += -DTHREAD_STACKSIZE_MAIN=14000
CFLAGS += -DDEVELHELP

include $(RIOTBASE)/Makefile.include
