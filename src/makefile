CC=gcc-5
POLARSSL_DIR=/Users/bbarr/opt/polarssl-1.1.8
CFLAGS=-g -Wall -I$(POLARSSL_DIR)/include -L$(POLARSSL_DIR)/library -lpolarssl

all: sign verify

sign: sign.c rsa_priv.c
	$(CC) $(CFLAGS) -o $@ sign.c rsa_priv.c
	mv $@ ../bin

verify: verify.c rsa_pub.c
	$(CC) $(CFLAGS) -o $@ verify.c rsa_pub.c
	mv $@ ../bin

rsa_priv.c:
ifdef POLARSSL_KEYS
	../bin/polarssl2c -f ../bogus_keys/polarssl_priv.txt > rsa_priv.c
else
	openssl rsa -inform PEM -noout -text -in ../bogus_keys/openssl_private.key | ../bin/openssl2c > rsa_priv.c
endif

rsa_pub.c:
ifdef POLARSSL_KEYS
	../bin/polarssl2c -f ../bogus_keys/polarssl_pub.txt > rsa_pub.c
else
	openssl rsa -inform PEM -noout -text -pubin -in ../bogus_keys/openssl_public.key | ../bin/openssl2c > rsa_pub.c
endif

clean:
	rm -rf **/*.o *.dSYM/ rsa_p*

.PHONY: all clean refresh
