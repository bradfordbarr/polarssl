The E in the public key is equal to 65537 not 17. The broadcom api may not be able
to handle public keys of that size. See if you can't change the E to 17 and see if
the public key check works.
