APPLICATION = hashing

RIOTBASE ?= $(CURDIR)/../../..
BOARD ?= native

USEMODULE += xtimer
USEMODULE += random
USEMODULE += hashes

CFLAGS += -DTHREAD_STACKSIZE_MAIN=14000
CFLAGS += -DDEVELHELP

include $(RIOTBASE)/Makefile.include
