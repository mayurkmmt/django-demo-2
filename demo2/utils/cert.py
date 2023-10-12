import ssl, re, logging

from abc import ABC
from OpenSSL import SSL, crypto

logger = logging.getLogger()


class SSLUtils(ABC):
    @classmethod
    def certificate_sans(cls, fullchain: str):
        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain)
        except Exception as e:
            logger.info("cert parse error: %s . %s" % (e, fullchain) )
            return []

        subject = cert.get_subject().commonName
        sans = set([subject])

        ext_count = cert.get_extension_count()

        for i in range(0, ext_count):
            ext = cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
                sans |= set(re.findall(r"DNS:([^, ]*)", san))

        return list(sans)


class CertValidator(ABC):

    def __init__(self, privkey, fullchain):
        self._privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, privkey)
        self._cert = crypto.load_certificate(crypto.FILETYPE_PEM, fullchain)
        self.fullchain = fullchain

    def check_cert_match(self):
        '''
        openssl pkey -in privateKey.key -pubout -outform pem | sha256sum
        openssl x509 -in certificate.crt -pubkey -noout -outform pem | sha256sum
        '''

        context2 = SSL.Context(SSL.TLSv1_METHOD)
        context2.use_privatekey(self._privkey)
        context2.use_certificate(self._cert)
        context2.check_privatekey()

        return True

    def check_hostname_match(self, domain, alias=[]):
        cert2 = {}
        sans = SSLUtils.certificate_sans(self.fullchain)

        cert2['subject'] = ((('commonName', list(sans)[0]),),)
        cert2['subjectAltName'] = (('DNS', s) for s in sans)

        for d in [domain] + alias:
            ssl.match_hostname(cert2, d)

        return True

