# shredder_encryptor

A small, dependency-free playground for encoding and encryption in Python.
The project bundles a handful of classical ciphers, an opinionated
encoding toolbox, a tiny framework for wiring ciphers together and a
small on-disk key store.  Everything relies on the standard library
only.

## Status

Early-stage example code.  The shipped ciphers (Vigenère, XOR-stream,
Feistel block ciphers, SHA-256 wrapper) are intended for learning
and experimentation; **do not use them to protect real secrets**.

## Installation

```bash
pip install shredder-encryptor
```

## Layout

```
shredder_encryptor/
  codec/         # encoding helpers (text, hex, base64, padding, ...)
  framework/     # BaseCipher, Pipeline, testing utilities
  cipher/        # ready-to-use algorithms (Vigenère, XorStream, ...)
  boom/          # irreversible (one-way) encryption primitives
  persistence.py # tiny on-disk key store
  version.py     # version metadata
tests/           # pytest suite (codec, framework, cipher, persistence, boom)
```

### `codec` — encoders in one place

```python
from shredder_encryptor import codec

codec.encode(b"hello")                # standard base64
codec.encode_url(b"hello")            # URL-safe base64
codec.pkcs7_pad(b"hi", 8)             # PKCS#7 block padding
codec.token_urlsafe(32)               # secrets.token_urlsafe wrapper
codec.hexdigest(b"hello", "sha1")     # hashlib wrapper
```

### `framework` — compose ciphers, test them

```python
from shredder_encryptor.cipher import VigenereCipher, XorStreamCipher
from shredder_encryptor.framework import Pipeline, assert_round_trip

pipeline = Pipeline([VigenereCipher(b"alpha"), XorStreamCipher(b"beta")])
assert_round_trip(pipeline, b"pipeline payload")
```

### `cipher` — concrete algorithms

```python
from shredder_encryptor.cipher import (
    VigenereCipher, XorStreamCipher, FeistelEcbCipher, FeistelCbcCipher,
    Sha256Hash,
)

ct = FeistelCbcCipher(b"my-key").encrypt(b"hello world")
pt = FeistelCbcCipher(b"my-key").decrypt(ct)
```

### `persistence` — small key store

```python
from shredder_encryptor.persistence import save_key, load_key, list_keys

save_key("api-token", b"super-secret-bytes")
print(list_keys())               # ['api-token']
load_key("api-token")            # b'super-secret-bytes'
```

Keys live in `~/.shredder_encryptor/keys/` by default with `0o600`
permissions on POSIX and ACL-stripped equivalents on Windows.

### `boom` — one-way encryption primitives

```python
from shredder_encryptor.boom import (
    ScrambleCipher, TruncateCipher, DiscardCipher, BloomFingerprint,
)
from shredder_encryptor.framework import assert_irreversible

assert_irreversible(TruncateCipher(keep=8), b"hello world")
digest = ScrambleCipher(b"my-key").encrypt(b"hello world")
fingerprint = BloomFingerprint(size=16, hashes=4).encrypt(b"hello world")
```

## Conventions

* Public APIs are typed and re-exported through each package's
  `__init__.py`.  Internal helpers start with an underscore.
* Cipher classes inherit from `framework.BaseCipher`; setting
  `DECRYPTABLE = False` marks a one-way cipher.
* `codec` mirrors the style of well-known libraries (e.g.
  `hashlib`, `secrets`, `base64`) but keeps a single import root.

## Security notice

The ciphers in `shredder_encryptor.cipher` are pedagogical.
`FeistelEcbCipher` / `FeistelCbcCipher` use a hand-rolled block
cipher with a tiny key size.  `VigenereCipher` and `XorStreamCipher`
provide no authentication.  For real-world cryptography, use a
vetted library such as `cryptography`.

## License

MIT.  See [LICENSE](LICENSE).