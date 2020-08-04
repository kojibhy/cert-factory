import datetime
import logging.config
from typing import Tuple
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID  # noqa

from core import settings

logger = logging.getLogger('cert_factory')


class DomainSignedCertificate:
    common_name: str = settings.DEFAULT_COMMON_NAME
    country_name: str = settings.DEFAULT_COUNTRY_NAME
    state_or_province_name: str = settings.DEFAULT_STATE_OR_PROVINCE_NAME
    locality_name: str = settings.DEFAULT_LOCALITY_NAME
    organization_name: str = settings.DEFAULT_ORGANIZATION_NAME

    def __init__(self, **options):
        for k, v in options.items():
            if hasattr(self, k) and v:
                self.__setattr__(k, v)

    @staticmethod
    def _private_key():
        return rsa.generate_private_key(public_exponent=65537,
                                        key_size=2048,
                                        backend=default_backend()
                                        )

    @staticmethod
    def to_string(cert, key):
        return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                                                encryption_algorithm=serialization.NoEncryption(),
                                                                                )

    def get_details(self):
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )

    def _root(self, days: int = settings.DEFAULT_EXPIRY_DATE):
        cert_key = self._private_key()
        _details = self.get_details()

        cert = x509.CertificateBuilder() \
            .subject_name(_details) \
            .issuer_name(_details) \
            .public_key(cert_key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days)) \
            .sign(cert_key, hashes.SHA256(), default_backend())

        logger.debug(cert)
        logger.debug(cert_key)
        return self.to_string(cert, cert_key)

    def build(self, root_key, root_cert, domain: str, days: int = settings.DEFAULT_EXPIRY_DATE) -> Tuple[bytes, bytes]:
        cert_key = self._private_key()
        cert = x509.CertificateBuilder() \
            .subject_name(self.get_details()) \
            .issuer_name(root_cert.issuer) \
            .public_key(cert_key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain),
                                                        x509.DNSName(f"*.{domain}")
                                                        ]
                                                       ), critical=False,
                           ) \
            .sign(root_key, hashes.SHA256(), default_backend())
        return self.to_string(cert, cert_key)

    @staticmethod
    def save_to_file(path, context: bytes) -> None:
        with open(path, 'wb') as f:
            f.write(context)

    @staticmethod
    def check_dir(path: str) -> None:
        if not os.path.exists(path):
            os.mkdir(path)

    @staticmethod
    def create_root(output, options=None, save=True) -> Tuple[bytes, bytes]:
        if not options:
            options = {}

        cls = DomainSignedCertificate(**options)

        cert_pem: bytes
        cert_key_pem: bytes

        cert_path, cert_key_path = os.path.join(output, settings.DEFAULT_ROOT_CERT_NAME), \
                                   os.path.join(output, settings.DEFAULT_ROOT_KEY_NAME)
        cert_pem, cert_key_pem = cls._root()
        if save:
            cls.save_to_file(cert_path, cert_pem)
            cls.save_to_file(cert_key_path, cert_key_pem)

        return cert_pem, cert_key_pem

    @staticmethod
    def create(domain: str, root_key, root_cert, output=None,
               options=None, save=True) -> Tuple[bytes, bytes]:
        if not output:
            output = settings.TEMP_DIR
        if not options:
            options = {}
        cls = DomainSignedCertificate(**options)

        cls.check_dir(output)

        cert_pem: bytes
        cert_key_pem: bytes

        cert_pem, cert_key_pem = cls.build(root_key, root_cert, domain)
        cert_path, cert_key_path = os.path.join(output, f"{domain}.crt"), os.path.join(output, f"{domain}.key")

        if save:
            cls.save_to_file(cert_path, cert_pem)
            cls.save_to_file(cert_key_path, cert_key_pem)

        return cert_pem, cert_key_pem
