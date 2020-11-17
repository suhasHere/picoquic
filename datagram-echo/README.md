datagram-echo
===============

This program is stripped down version of picoquidemo's siduck 
implementation
It shows a continuous sender sending 40 bytes packets approximately 
very 20 ms.

Build
=====
Same as for picoquic.
```
cmake .
make all
```

To run as server
================
```
./forty-bytes
```

To run as client
================
```
./forty-bytes localhost 4443
```

The program reuses server cert/key file from certs/ and 
hence is hardcoded

Observation
===========

