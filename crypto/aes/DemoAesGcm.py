#!/usr/bin/env python3
# ----------------------------------------------------------------
# Copyright (c) 2023 Matteo Bertozzi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# pip3 install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os


def aes_generate_key():
    # 256bit random data
    return os.urandom(32)


def aes_gcm_encrypt(key: bytes, message: bytes) -> bytes:
    # Generate 96bit Initialization Vector
    iv = os.urandom(12)

    # Init AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    # Encrypt 'message'
    aes_data = encryptor.update(message) + encryptor.finalize()
    # Get the full cipherText: IV + Encrypted-Message + Auth-Tag
    ciphertext = iv + aes_data + encryptor.tag
    return ciphertext


def aes_gcm_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[0:12]
    aes_data = ciphertext[12:-16]
    tag = ciphertext[-16:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    text = decryptor.update(aes_data) + decryptor.finalize()
    return text


if __name__ == '__main__':
    MESSAGE = b'hello world'

    aes_key = aes_generate_key()
    ciphertext = aes_gcm_encrypt(aes_key, MESSAGE)
    plaintext = aes_gcm_decrypt(aes_key, ciphertext)
    assert plaintext == MESSAGE, (plaintext, MESSAGE)

    print('AES key', base64.b64encode(aes_key))
    print('Ciphertext', base64.b64encode(ciphertext))
