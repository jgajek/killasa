# killasa

Vulnerability Test for CVE-2016-1287 (Cisco ASA invalid IKE fragment length)

Negotiates IKEv2 SA with Cisco fragmentation enabled, then sends
two IKE fragments, one of which has an invalid length of 1 octet.
