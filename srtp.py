#!/usr/bin/env python3

from struct import pack, unpack
from itertools import count
from Crypto.Cipher import AES
import hmac
import hashlib
import io
import sys

import unittest

from binascii import unhexlify as ux
from binascii import hexlify
from itertools import islice

from collections import namedtuple

def xor(a, b):
  assert(len(a) == len(b))
  c = bytes([a[i] ^ b[i] for i in range(len(a))])
  return c

def div(a, t):
  if t == 0: return 0
  else: return a//t

Rtp = namedtuple('Rtp', 'V P X CC M PT seq ts ssrc csrcs hdr payload')

def rtp_pop(b):
  f = io.BytesIO(b)

  hdr = b''

  data = f.read(12)
  assert(len(data) == 12)
  hdr += data
  (a, b, seq, ts, ssrc) = unpack('!BBHII', data)

  V = (a & 0xc0)>>6
  P = (a & 0x20)>>5
  X = (a & 0x10)>>4
  CC = (a & 0x0f)
  assert(V == 0 or (V == 2 and X == 0))

  M = (b & 0x80)>>7
  PT = (b & 0x7f)

  csrcs = []
  for i in range(CC):
    csrc = f.read(4)
    assert(len(csrc) == 4)
    hdr += csrc
    csrcs.append(unpack('!I', csrc)[0])

  payload = f.read()

  return Rtp(V, P, X, CC, M, PT, seq, ts, ssrc, csrcs, hdr, payload)

def kdf(key, salt, label, n, index=0):
  assert(0 <= label and label <= 2**8-1)
  assert(0 <= index and index <= 2**48-1)
  assert(len(salt) == 14)
  assert(len(key) in [16, 24, 32])

  data = b''

  x = pack('!Q', label)
  shifted = salt + b'\x00\x00'

  aes = AES.new(key, mode=AES.MODE_ECB)

  for i in count(0):
    iv = x + pack('!Q', (index<<16)|(i))
    assert(len(iv) == 16)
    iv = xor(iv, shifted)

    block = aes.encrypt(iv)
    data += block
    if len(data) >= n:
      break

  return data[:n]

def keystream(key, salt, ssrc, seq, n, roc=0):
  assert(len(key) in [16, 24, 32])
  assert(len(salt) == 14)
  assert(0 <= ssrc and ssrc < 2**32)
  assert(0 <= seq and seq < 2**16)
  assert(0 <= roc and roc < 2**32)

  data = b''

  iv = salt + b'\x00\x00'
  x = b'\x00'*4 + pack('!I', ssrc) + pack('!I', roc)
  x += pack('!H', seq)
  assert(len(x) == 14)

  aes = AES.new(key, mode=AES.MODE_ECB)

  for i in count(0):
    z = x + pack('!H', i)
    assert(len(z) == 16)

    z = xor(z, iv)

    block = aes.encrypt(z)

    data += block
    if len(data) >= n:
      break

  return data[:n]

# data shall include rtp header as sent
def crypt(key, salt, data):
  rtp = rtp_pop(data)
  assert(rtp.V == 0 or (rtp.V == 2 and rtp.X == 0))

  n = len(rtp.payload)
  ks = keystream(key, salt, rtp.ssrc, rtp.seq, n, 0)
  return rtp.hdr + xor(rtp.payload, ks)

def auth(key, data, roc=0):
  ctx = hmac.new(key, digestmod=hashlib.sha1)
  ctx.update(data)
  ctx.update(pack('!I', roc))
  return ctx.digest()

# AES-{128, 192, 256} CM
# HMAC-SHA1 80 or 32
# no ROC in anyway
class Context:
  def __init__(self, master_key, master_salt, tag_len):
    assert(len(master_key) in [16, 24, 32])
    assert(tag_len in [4, 10])

    self.master_key = master_key
    assert(len(master_salt) == 14)
    self.master_salt = master_salt
    self.taglen = tag_len

    SRTP_CRYPT = 0
    SRTP_AUTH = 1
    SRTP_SALT = 2

    SRTCP_CRYPT = 3
    SRTCP_AUTH = 4
    SRTCP_SALT = 5

    # derive SRTP material
    self.srtp_cipher_key = kdf(self.master_key, self.master_salt, SRTP_CRYPT, len(master_key))
    self.srtp_auth_key = kdf(self.master_key, self.master_salt, SRTP_AUTH, 20)
    self.srtp_salt = kdf(self.master_key, self.master_salt, SRTP_SALT, 14)

    self.srtcp_cipher_key = kdf(self.master_key, self.master_salt, SRTCP_CRYPT, len(master_key))
    self.srtcp_auth_key = kdf(self.master_key, self.master_salt, SRTCP_AUTH, 20)
    self.srtcp_salt = kdf(self.master_key, self.master_salt, SRTCP_SALT, 14)

  def srtp_protect(self, data):
    ciphered = crypt(self.srtp_cipher_key, self.srtp_salt, data)
    return ciphered + auth(self.srtp_auth_key, ciphered)[:self.taglen]

  def srtp_unprotect(self, data):
    ciphered, tag = data[:-self.taglen], data[-self.taglen:]
    assert(len(tag) == self.taglen)

    if auth(self.srtp_auth_key, ciphered)[:self.taglen] != tag:
      return

    plain = crypt(self.srtp_cipher_key, self.srtp_salt, ciphered)
    return plain


class AES128_SHA80(unittest.TestCase):
  def setUp(self):
    self.key = ux('e1f97a0d3e018be0d64fa32c06de4139')
    self.salt = ux('0ec675ad498afeebb6960b3aabe6')
    self.ssrc = 0xcafebabe
    self.ctx = Context(self.key, self.salt, 10)

  def test_kdf(self):
    x = kdf(self.key, self.salt, 0, 16)
    self.assertEqual(x, b'\xC6\x1E\x7A\x93\x74\x4F\x39\xEE\x10\x73\x4A\xFE\x3F\xF7\xA0\x87')

    x = kdf(self.key, self.salt, 2, 14)
    self.assertEqual(x, b'\x30\xCB\xBC\x08\x86\x3D\x8C\x85\xD4\x9D\xB3\x4A\x9A\xE1')

    x = kdf(self.key, self.salt, 1, 94)
    self.assertEqual(x, b'\xCE\xBE\x32\x1F\x6F\xF7\x71\x6B\x6F\xD4\xAB\x49\xAF\x25\x6A\x15' +
    b'\x6D\x38\xBA\xA4\x8F\x0A\x0A\xCF\x3C\x34\xE2\x35\x9E\x6C\xDB\xCE' +
    b'\xE0\x49\x64\x6C\x43\xD9\x32\x7A\xD1\x75\x57\x8E\xF7\x22\x70\x98' +
    b'\x63\x71\xC1\x0C\x9A\x36\x9A\xC2\xF9\x4A\x8C\x5F\xBC\xDD\xDC\x25' +
    b'\x6D\x6E\x91\x9A\x48\xB6\x10\xEF\x17\xC2\x04\x1E\x47\x40\x35\x76' +
    b'\x6B\x68\x64\x2C\x59\xBB\xFC\x2F\x34\xDB\x60\xDB\xDF\xB2')

  def test_protect(self):
    plaintext = ux('800f1234decafbadcafebabe' + 'ab'*16)
    ciphertext = ux('800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402b78d6acc99ea179b8dbb')
    assert(len(ciphertext) == len(plaintext) + 10)

    data = self.ctx.srtp_protect(plaintext)
    assert(len(data) == len(plaintext) + 10)
    assert(data == ciphertext)

  def test_unprotect(self):
    plaintext = ux('800f1234decafbadcafebabe' + 'ab'*16)
    ciphertext = ux('800f1234decafbadcafebabe4e55dc4ce79978d88ca4d215949d2402b78d6acc99ea179b8dbb')

    data = self.ctx.srtp_unprotect(ciphertext)
    assert(data == plaintext)


class AES256_SHA80(unittest.TestCase):
  def setUp(self):
    self.key = ux('f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6')
    self.salt = ux('3b04803de51ee7c96423ab5b78d2')
    self.ssrc = 0xcafebabe
    self.ctx = Context(self.key, self.salt, 10)

  def test_kdf(self):
    x = kdf(self.key, self.salt, 0, 32)
    self.assertEqual(hexlify(x), b'5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4')

    x = kdf(self.key, self.salt, 2, 14)
    self.assertEqual(hexlify(x), b'fa31791685ca444a9e07c6c64e93')

    x = kdf(self.key, self.salt, 1, 20)
    self.assertEqual(hexlify(x), b'fd9c32d39ed5fbb5a9dc96b30818454d1313dc05')

  def test_protect(self):
    plaintext = ux('800f1234decafbadcafebabe' + 'ab'*16)
    ciphertext = ux('800f1234decafbadcafebabe' + 'f1d9de17ff251ff1aa007774' +
    'b0b4b40da08d9d9a5b3a55d8873b')
    self.assertEqual(len(ciphertext), len(plaintext) + 10)

    data = self.ctx.srtp_protect(plaintext)
    self.assertEqual(len(data), len(plaintext) + 10)
    self.assertEqual(data, ciphertext)

  def test_unprotect(self):
    plaintext = ux('800f1234decafbadcafebabe' + 'ab'*16)
    ciphertext = ux('800f1234decafbadcafebabe' + 'f1d9de17ff251ff1aa007774' +
    'b0b4b40da08d9d9a5b3a55d8873b')

    data = self.ctx.srtp_unprotect(ciphertext)
    self.assertEqual(data, plaintext)

if __name__ == '__main__':
  unittest.main()
