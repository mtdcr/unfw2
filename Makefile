#!/usr/bin/make -f

CFLAGS := -Wall -Wextra -std=c11
LDLIBS := $(shell pkg-config --libs libcrypto)

TARGETS := unfw2

default: $(TARGETS)

clean:
	$(RM) $(TARGETS)
