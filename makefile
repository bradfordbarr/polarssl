SHELL=/usr/bin/env bash
VERIFY_FILE=./src/sign.c

default: all

all:
	$(MAKE) -e -C src all

clean:
	$(MAKE) -e -C src clean
	rm -rf ./tmp ./bin/sign ./bin/verify

refresh:
ifdef POLARSSL_KEYS
	cd ./bogus_keys; ../bin/polarsslgen
else
	cd ./bogus_keys; ../bin/opensslgen
endif

.PHONY: all clean refresh
