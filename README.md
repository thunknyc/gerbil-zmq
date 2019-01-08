# gerbil-zmq
ZeroMQ support for Gerbil Scheme

## Building

`$ gxc -cc-options "-I/usr/local/opt/zmq/include -L/usr/local/opt/zmq/lib -lzmq" zmq.ss`

## Status

Functions and constants for the public ZeroMQ API as documented in the
zmq(7) man page but no effort has yet been undertaken to make those
functions and constants usable in an everyday Gerbil prgoram.