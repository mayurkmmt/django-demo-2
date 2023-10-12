import requests


rr_types = {
    1: 'A',
    28: 'AAAA',
    18: 'AFSDB',
    42: 'APL',
    257: 'CAA',
    60: 'CDNSKEY',
    59: 'CDS',
    37: 'CERT',
    5: 'CNAME',
    62: 'CSYNC',
    49: 'DHCID',
    32769: 'DLV',
    39: 'DNAME',
    48: 'DNSKEY',
    43: 'DS',
    108: 'EUI48',
    109: 'EUI64',
    13: 'HINFO',
    55: 'HIP',
    45: 'IPSECKEY',
    25: 'KEY',
    36: 'KX',
    29: 'LOC',
    15: 'MX',
    35: 'NAPTR',
    2: 'NS',
    47: 'NSEC',
    50: 'NSEC3',
    51: 'NSEC3PARAM',
    61: 'OPENPGPKEY',
    12: 'PTR',
    46: 'RRSIG',
    17: 'RP',
    24: 'SIG',
    53: 'SMIMEA',
    6: 'SOA',
    33: 'SRV',
    44: 'SSHFP',
    32768: 'TA',
    249: 'TKEY',
    52: 'TLSA',
    250: 'TSIG',
    16: 'TXT',
    256: 'URI',
    63: 'ZONEMD',
    64: 'SVCB',
    65: 'HTTPS'
}


def dig_domain(domain):
    try:
        res = requests.get(f"https://dns.google.com/resolve?name={domain}", timeout=2)
        return res.json()
    except:
        return None
