import time

from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate

from strelka import strelka


class ScanX509(strelka.Scanner):
    """Collects metadata from x509 and CRL files.

    x509 extensions require cleanup and may be improperly formatted.

    Options:
        type: String that determines the type of x509 certificate being
            scanned. Must be either 'der' or 'pem'.
            Defaults to empty string.
    """
    def scan(self, data, file, options, expire_at):
        file_type = options.get('type', '')

        if file_type == 'der':
            cert = load_der_x509_certificate(data)
        else:
            cert = load_pem_x509_certificate(data)


        self.event['issuer'] = str(cert.issuer)
        self.event['subject'] = str(cert.subject)
        self.event['serial_number'] = str(cert.serial_number)
        self.event['fingerprint'] = cert.fingerprint(hashes.MD5())
        self.event['version'] = cert.version
        self.event['not_after'] = int(cert.not_valid_after.strftime('%s'))
        self.event['not_before'] = int(cert.not_valid_before.strftime('%s'))
        if self.event['not_after'] < time.time():
            self.event['expired'] = True
        else:
            self.event['expired'] = False
