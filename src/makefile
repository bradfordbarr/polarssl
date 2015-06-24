CC=gcc-5
POLARSSL_DIR=/Users/bbarr/opt/polarssl-1.1.8
CFLAGS=-g -Wall -I$(POLARSSL_DIR)/include -L$(POLARSSL_DIR)/library -lpolarssl

sign: sign.c rsa_priv.c
	$(CC) $(CFLAGS) -o sign sign.c rsa_priv.c

verify: verify.c rsa_pub.c
	$(CC) $(CFLAGS) -o verify verify.c rsa_pub.c

rsa_priv.c:
	../bin/key2c -f ../bogus_keys/rsa_priv.txt > rsa_priv.c

rsa_pub.c:
	../bin/key2c -f ../bogus_keys/rsa_pub.txt > rsa_pub.c

clean:
	rm -rf **/*.o **/*.dSYM rsa_priv.c sign verify

.PHONY: clean
