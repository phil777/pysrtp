#!/usr/bin/env python3

from struct import pack, unpack
from collections import namedtuple
from srtp import Context, rtp_pop
from base64 import b64decode
import datetime

import sys

Pkt = namedtuple('Pkt', 'ts caplen bytes')

def gen_packets(name, offset=0):
  '''Parse and yield packets from pcap file.'''

  f = open(name, 'rb')
  magic = f.read(4)
  assert(len(magic) == 4)

  (magic,) = unpack('=L', magic)
  if magic == 0xa1b2c3d4:
    swapped = '<'
  elif magic == 0xd4c3b2a1:
    swapped = '>'
  else:
    print >>sys.stderr, 'pcap magic unknown!'
    sys.exit(1)
  fhdr = f.read(20)
  assert(len(fhdr) == 20)
  (major, minor, zone, sigfigs, snaplen, dlt) = unpack(swapped + 'HHIIII', fhdr)

  while True:
    phdr = f.read(16)
    if len(phdr) == 0:
      break
    assert(len(phdr) == 16)

    (sec, usec, caplen, l) = unpack(swapped + 'IIII', phdr)
    content = f.read(caplen)
    assert(len(content) == caplen)

    assert(len(content) == caplen)
    yield Pkt(sec + usec*0.000001, caplen, bytes(content[offset:]))

def pkt_dump(pkt):
  '''Dump packet to text2pcap expected input format.'''

  t = datetime.datetime.fromtimestamp(pkt.ts)
  print(t.strftime('%H:%M:%S.%f'))

  content = pkt.bytes
  for i in range(0, len(content), 16):
    print('%04x  %s' % (i, ' '.join(['%02x' % c for c in content[i:i+16]])))

raw = b64decode('aSBrbm93IGFsbCB5b3VyIGxpdHRsZSBzZWNyZXRz')
keylen = len(raw)-14
assert(keylen in [16, 24, 32])

(key, salt) = (raw[:keylen], raw[keylen:])
ctx = Context(key, salt, 10)

for pkt in gen_packets('marseillaise-srtp.pcap', 42):
  plain = ctx.srtp_unprotect(pkt.bytes)
  assert(plain)

  pkt = Pkt(pkt.ts, pkt.caplen, plain)
  pkt_dump(pkt)
