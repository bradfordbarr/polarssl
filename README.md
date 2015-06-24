#Polarssl Examples

A couple of quick examples to make sure I understand how Polarssl works.

```sh
cd src/
make clean sign verify
./sign $FILE > $SIGNATURE
./verify $FILE $SIGNATURE
```
