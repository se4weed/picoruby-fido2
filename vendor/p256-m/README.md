# p256-m

This directory vendors the fixed-width P-256 implementation from
Mbed TLS's `3rdparty/p256-m/p256-m` directory. It is compiled directly into
`picoruby-fido2`; it does not link to or require Mbed TLS.

The vendored source is used under Apache-2.0. See `LICENSE`.

Local changes:

- removed Mbed TLS and PSA header/configuration dependencies;
- replaced Mbed TLS zeroization with a local volatile implementation;
- delegated random-byte generation to the embedding FIDO2 module.
