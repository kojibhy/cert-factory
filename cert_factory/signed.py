import datetime
import logging.config
import os
import random
from typing import Tuple, Union, Dict, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.base import Certificate  # noqa
from cryptography.x509.oid import NameOID  # noqa

import default_settings
from choices import COUNTRY_CODE_ISO_3166, NameOID_CHOICES

logger = logging.getLogger('certfactory')


class CertificateFactory:
    # Root certificates also typically have long periods of validity, compared to intermediate certificates.
    # They will often last for 10 or 20 years, which gives enough time to prepare for when they expire.
    # SSL Certificate Validity Period to Be Capped at 398 Days Max From September 1, 2020, Safari, Chrome and Firefox
    # will no longer trust new SSL certificates with validity of more than 398 days.
    default_root_expiry_date = 365 * 5  # 10 years
    default_expiry_date = 90  # default for domain 3 month
    expiry_date: int = None
    # for root CA we need add Root Name example: Chambers of Commerce Root - 2008
    commonName: Union[str, None] = "Demo"
    countryName: Union[str, None] = None
    serialNumber: Union[str, None] = None
    surname: Union[str, None] = None
    givenName: Union[str, None] = None
    title: Union[str, None] = None
    localityName: Union[str, None] = "<Not Available>"
    stateOrProvinceName: Union[str, None] = "<Not Available>"
    streetAddress: Union[str, None] = "<Not Available>"
    organizationName: Union[str, None] = "Super Demo Org"
    organizationalUnitName: Union[str, None] = "<Not Part Of Certificate>"

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k) and v:
                self.__setattr__(k, v)

        if not self.countryName:
            self.countryName = self.get_country_name()

    @staticmethod
    def get_country_name():
        return random.choice(COUNTRY_CODE_ISO_3166)

    @staticmethod
    def to_bytes(rsa_key, cert) -> Tuple[bytes, bytes]:
        return rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ), cert.public_bytes(serialization.Encoding.PEM)

    def generate_x509_details(self) -> x509.Name:
        name_attributes = []
        for k, v in NameOID_CHOICES.items():
            value = getattr(self, v, None)
            if value is not None:
                name_attributes.append(x509.NameAttribute(k, value))
        return x509.Name(name_attributes)

    @staticmethod
    def _private_key():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_root(self) -> Tuple[bytes, bytes]:
        if self.expiry_date is None:
            expiry_date = self.default_root_expiry_date
        else:
            expiry_date = self.expiry_date

        rsa_key_pair = self._private_key()
        x509_details = self.generate_x509_details()
        cert = x509.CertificateBuilder() \
            .subject_name(x509_details) \
            .issuer_name(x509_details) \
            .public_key(rsa_key_pair.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=expiry_date)) \
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
            .sign(rsa_key_pair, hashes.SHA256(), default_backend())

        return self.to_bytes(rsa_key_pair, cert)

    def generate_domain(self, domain: str, root_key: RSAPrivateKey, root_cert: Certificate) -> Tuple[bytes, bytes]:
        if self.expiry_date is None:
            expiry_date = self.default_expiry_date
        else:
            expiry_date = self.expiry_date

        cert_pkey = self._private_key()
        cert = x509.CertificateBuilder() \
            .subject_name(self.generate_x509_details()) \
            .issuer_name(root_cert.issuer) \
            .public_key(cert_pkey.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=expiry_date)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain),
                                                        x509.DNSName(f"*.{domain}")
                                                        ]
                                                       ), critical=False,
                           ) \
            .sign(root_key, hashes.SHA256(), default_backend())
        return self.to_bytes(cert_pkey, cert)


class CertificateStorage:
    pass


class DomainRequiredException(Exception):
    pass


class CertificateManager:
    ROOT_KEY_NAME = "rootCA.key"
    ROOT_CERT_NAME = "rootCA.crt"
    messages = []

    def __init__(self, certificates_dir: str = None, options: Dict = None):

        if not options:
            options = {}

        self.certificates_dir = default_settings.CERTIFICATES_DIR if certificates_dir is None else certificates_dir

        if not os.path.exists(self.certificates_dir):
            os.mkdir(self.certificates_dir)

        self.factory = CertificateFactory(**options)

    @staticmethod
    def save_to_file(path, context: bytes) -> str:
        with open(path, 'wb') as f:
            f.write(context)
        return path

    @staticmethod
    def serialize_pkey(content: bytes) -> RSAPrivateKey:
        return serialization.load_pem_private_key(content, password=None, backend=default_backend())

    @staticmethod
    def serialize_certificate(content: bytes) -> Certificate:
        return x509.load_pem_x509_certificate(content, default_backend())

    @staticmethod
    def load_file(path) -> bytes:
        with open(path, "rb") as f:
            content = f.read()
        return content

    def get_root_pair(self, rkey_path, rcert_path) -> Tuple[RSAPrivateKey, Certificate]:
        rkey_path = os.path.join(self.certificates_dir, self.ROOT_KEY_NAME) if rkey_path is None else rkey_path
        rcert_path = os.path.join(self.certificates_dir, self.ROOT_CERT_NAME) if rcert_path is None else rcert_path
        message = f"Get:\n Root Key {rkey_path}\nNew Root Certificate {rcert_path}"
        self.messages.append(message)
        return self.serialize_pkey(self.load_file(rkey_path)), self.serialize_certificate(self.load_file(rcert_path))

    def create_root_pair(self, rkey_path, rcert_path) -> Tuple[RSAPrivateKey, Certificate]:
        rkey_path = os.path.join(self.certificates_dir, self.ROOT_KEY_NAME) if rkey_path is None else rkey_path
        rcert_path = os.path.join(self.certificates_dir, self.ROOT_CERT_NAME) if rcert_path is None else rcert_path

        pkey: bytes
        cert: bytes
        pkey, cert = self.factory.generate_root()
        self.save_to_file(rkey_path, pkey)
        self.save_to_file(rcert_path, cert)

        message = f"Created:\nNew Root Key {rkey_path}\nNew Root Certificate {rcert_path}"
        self.messages.append(message)
        return self.serialize_pkey(pkey), self.serialize_certificate(cert)

    def get_or_create_sign_pair(self, rkey_path, rcert_path) -> Tuple[RSAPrivateKey, Certificate, bool]:

        root_key: RSAPrivateKey
        root_cert: Certificate

        try:
            root_key, root_cert = self.get_root_pair(rkey_path, rcert_path)
            return root_key, root_cert, False
        except Exception as exc:
            root_key, root_cert = self.create_root_pair(rkey_path, rcert_path)
            return root_key, root_cert, True

    def save_and_sign(self, domains: List, rkey_path: str = None, rcert_path: str = None) -> List[str]:
        if not domains:
            raise DomainRequiredException()

        rkey, rcert, is_created = self.get_or_create_sign_pair(rkey_path, rcert_path)

        for domain in domains:
            domain_key: bytes
            domain_key: bytes
            domain_key, domain_cert = self.factory.generate_domain(domain, rkey, rcert)

            domain_key_path = self.save_to_file(os.path.join(self.certificates_dir, f"{domain}.key"), domain_key)
            domain_cert_path = self.save_to_file(os.path.join(self.certificates_dir, f"{domain}.crt"), domain_cert)

            message = f"Created:\nNew Domain Key {domain_key_path}\nNew Domain Certificate {domain_cert_path}"
            self.messages.append(message)
            logger.info(message)
        return self.messages
