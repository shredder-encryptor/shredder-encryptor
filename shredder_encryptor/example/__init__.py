"""
An Example Encryptor 

Type: Caesar shift encryption
"""

from .decrypt import SampleDecrypt
from .encrypt import SampleEncrypt

NAME = "example-encryptor"
VERSION = 1
DECRYPTABLE = True
NON_DECRYPTABLE = False

__all__ = [
    "SampleDecrypt",
    "SampleEncrypt",
]
