# pysrtp
Pythonic implementation of SRTP (rfc 3711). Uses Python3.

## Dependencies
Symmetric ciphers have not made their way to stdlib, so you will need to use the excellent [PyCrypto] (https://www.dlitz.net/software/pycrypto/).

## Quick tutorial
srtp.py contains a Context class, which derives keystreams for common labels. Context class contains srtp_protect and srtp_unprotect methods. Both expect data at RTP level.

A Pythonic version of srtp-decrypt is also present, so you can check srtp.Context usage.

To decipher the sample trace, use the command line: ./srtp-decrypt.py | text2pcap -t "%H:%M:%S." -u 10000,10000 - - > marseillaise-rtp.pcap. It will create a pcap containing unprotected RTP packets which can be listen using Wireshark features.

## Test vectors
By executing srtp.py on its own, you will execute self-contained tests, based on AES128 HMACSHA1-80, and AES256 HMACSHA1-80.
