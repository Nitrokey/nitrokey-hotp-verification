SRCDIR=src
PKGCONFIG=pkg-config

SRC:= \
	$(SRCDIR)/crc32.c \
	$(SRCDIR)/device.c \
	$(SRCDIR)/operations.c \
	$(SRCDIR)/dev_commands.c \
	$(SRCDIR)/base32.c \
	$(SRCDIR)/random_data.c \
	$(SRCDIR)/min.c \
	$(SRCDIR)/version.c \
	$(SRCDIR)/return_codes.c \
	$(SRCDIR)/main.c \
	$(SRCDIR)/tlv.c \
	$(SRCDIR)/ccid.c \
	$(SRCDIR)/operations_ccid.c

SRC += \
	./hidapi/libusb/hid.c

HEADERS := \
	$(SRCDIR)/crc32.h \
	$(SRCDIR)/structs.h \
	$(SRCDIR)/device.h \
	$(SRCDIR)/operations.h \
	$(SRCDIR)/dev_commands.h \
	$(SRCDIR)/base32.h \
	$(SRCDIR)/command_id.h \
	$(SRCDIR)/random_data.h \
	$(SRCDIR)/min.h \
	$(SRCDIR)/settings.h \
	$(SRCDIR)/version.h \
	$(SRCDIR)/return_codes.h \
	$(SRCDIR)/ccid.h \
	$(SRCDIR)/tlv.h \
	$(SRCDIR)/operations_ccid.h

OBJS := ${SRC:.c=.o}

HIDAPI_INC=hidapi
INC:= \
	-I$(SRCDIR) \
	-I$(HIDAPI_INC) \
	-I$(HIDAPI_INC)/hidapi \

LIBUSB_FLAGS=$(shell $(PKGCONFIG) --cflags libusb-1.0)
LIBUSB_LIB=$(shell $(PKGCONFIG) --libs libusb-1.0)

CFLAGS= -Wall -Wextra -fno-guess-branch-probability -Wdate-time -frandom-seed=42 -O2 -gno-record-gcc-switches -DNDEBUG -fdebug-prefix-map=${PWD}=heads -c -std=gnu11 -DNK_REMOVE_PTHREAD $(LIBUSB_FLAGS)

OUTDIR=
OUT=hotp_verification
LDFLAGS=$(LIBUSB_LIB)

all: $(OUT)
	ls -lh $^
	sha256sum $^

clean:
	-rm $(OBJS) $(OUT) $(SRCDIR)/version.c

$(OUT): $(OBJS)
	$(CC) $^ $(LDFLAGS)  -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INC) -o $@ $<

GITVERSION=$(shell git describe)
$(SRCDIR)/version.c: $(SRCDIR)/version.c.in
	sed "s!@GIT_VERSION_PLACEHOLDER@!$(GITVERSION)!g" < $< >$@

.PRECIOUS: %.o

INSTALL=/usr/local/
.PHONY: install
install:
	cp -v $(OUT) $(INSTALL)/bin

.PHONY: github_sha
GVER=$(shell git rev-parse HEAD)
libremkey_url := https://github.com/Nitrokey/nitrokey-hotp-verification/archive/$(GVER).tar.gz
github_sha:
	wget -c $(libremkey_url)
	sha256sum $(GVER).tar.gz
	@echo $(GVER)

.PHONY: format
format:
	clang-format -i $(shell find src -type f | grep -v base32)
	clang-format -i tests/test* ./test_ccid.cpp
