# vmux

vmux is a secure, multipath network protocol over UDP. It is derived from
[MUD](https://github.com/angt/mud) by Adrien Gallouët, used under its original
BSD-3-Clause licence (see `LICENSE`). It is the transport library of Vortex.


### Compatibility

Linux is the platform of choice but it was successfully ported to OpenBSD and OSX.

### Dependencies

 * A recent version of GCC or Clang.
 * [libsodium](https://github.com/jedisct1/libsodium).

### Security

Encryption and authentication is done with AEGIS256 when aesni is available otherwise ChaCha20-Poly1305 is used.
The Diffie-Hellman function X25519 is used for key exchange.

### Issues

For feature requests and bug reports about this fork, use the issue tracker of
the repository you obtained it from. The original project is at
[angt/mud](https://github.com/angt/mud/issues).
