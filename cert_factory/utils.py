import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import Certificate  # noqa

from core import settings


def load(path):
    with open(path, "r") as f:
        content = f.read()
    return content


def load_pem_private_key(path=None):
    if not path:
        path = os.path.join(settings.CONFIG_DIR, settings.DEFAULT_ROOT_KEY_NAME)
    content = load(path)
    return serialization.load_pem_private_key(
        content.encode("ascii"), password=None, backend=default_backend()
    )


def load_pem_x509_certificate(path=None) -> Certificate:
    if not path:
        path = os.path.join(settings.CONFIG_DIR, settings.DEFAULT_ROOT_CERT_NAME)
    content = load(path)
    return x509.load_pem_x509_certificate(
        content.encode("ascii"), default_backend()
    )


def get_output(path=None):
    if not path:
        return settings.CONFIG_DIR
    return path
