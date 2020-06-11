SRCDIR=.
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
	$(SRCDIR)/main.c

SRC += \
	$(SRCDIR)/hidapi/libusb/hid.c

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
OUT=nitrokey_hotp_verification
OUT2=libremkey_hotp_verification
LDFLAGS=$(LIBUSB_LIB)

all: $(OUT) $(OUT2)
	ls -lh $^
	sha256sum $^

clean:
	-rm $(OBJS) $(OUT) version.c

$(OUT2): $(OUT)
	cp $< $@

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
	cp -v $(OUT) $(OUT2) $(INSTALL)/bin

.PHONY: github_sha
GVER=$(shell git rev-parse HEAD)
libremkey_url := https://github.com/Nitrokey/nitrokey-hotp-verification/archive/$(GVER).tar.gz
github_sha:
	wget -c $(libremkey_url)
	sha256sum $(GVER).tar.gz
	@echo $(GVER)