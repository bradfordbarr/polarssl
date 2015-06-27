#Polarssl Examples

Some sample code to prove interoperability between PolarSSL generated RSA keys
and OpenSSL generated RSA keys. The keys are parsed using a NodeJS program and
turned into C buffers that can be used in executables. C application development
would just use the key files as is and parse them using PolarSSL or OpenSSL APIs.
I'm working with embedded C without a filesystem. C buffers seemed to be the
easiest way to ingest the data.

To build, run:

```sh
make
```

This will create two executables, `sign` and `verify`. These executables will be 
placed in the `./bin` directory. By default the application will use the openssl
keys provided. To use PolarSSL keys run:

```sh
make POLARSSL_KEYS=1
```

To regenerate keys run:

```sh
make refresh
```

To generate a signature run:

```sh
sign $INFILE > $OUTFILE
```

To verify the signature run:

```sh
verify $INFILE $OUTFILE
```

Where `$INFILE` and `$OUTFILE` are the same files from the `sign` command.
