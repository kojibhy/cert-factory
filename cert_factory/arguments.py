#!/usr/bin/env python3

import argparse
import logging
import os
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from c_factory import DomainSignedCertificate
from core import settings
from utils import load_pem_private_key, load_pem_x509_certificate

logger = logging.getLogger('cert_factory')


# check project structure.

class OutPutArgument:
    def __call__(self, parser: argparse.ArgumentParser, *args, **kwargs):
        parser.add_argument(
            '-o',
            '--output',
            default=settings.CONFIG_DIR,
            required=False,
            help=''
        )


class SubjectArgument:
    def __call__(self, parser: argparse.ArgumentParser, *args, **kwargs):
        parser.add_argument(
            '--common_name',
            default=None,
            required=False,
            help=''
        )
        parser.add_argument(
            '--country_name',
            default=None,
            required=False,
            help=''
        )
        parser.add_argument(
            '--locality_name',
            default=None,
            required=False,
            help=''
        )
        parser.add_argument(
            '--organization_name',
            default=None,
            required=False,
            help=''
        )
        parser.add_argument(
            '--state_or_province_name',
            default=None,
            required=False,
            help=''
        )


class Args:
    usage = """
    ./cert_factory.py <command> [<args>] -h 
        The most commonly used commands are:
        - cert
        - root
    """
    epilog = ""
    description = ""

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            usage=self.usage,
            epilog=self.epilog,
            description=self.description,
        )

    def __call__(self, *args, **kwargs):
        self.parser.add_argument('command', help='Sub-Command to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = self.parser.parse_args(sys.argv[1:2])

        sub_command = "command_" + args.command
        if not hasattr(self, sub_command):
            print('Unrecognized command')
            self.parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        handler = getattr(self, sub_command)
        parser = argparse.ArgumentParser(description='Base setup Sub-Command')
        try:
            handler(parser)
        except Exception as exc:
            print(exc)

    def get_options(self, args):
        return {
            "common_name": args.common_name,
            "country_name": args.country_name,
            "locality_name": args.locality_name,
            "organization_name": args.organization_name,
            "state_or_province_name": args.state_or_province_name,
        }

    def command_cert(self, parser: argparse.ArgumentParser = None):
        parser.add_argument(
            '-rK',
            '--rootKey',
            default=None,
            help='',
        )
        parser.add_argument(
            '-rCA',
            '--rootCertificate',
            default=None,
            help='',
        )
        parser.add_argument(
            '-d',
            '--domain',
            nargs='+',
            help='',
            required=True
        )
        args_cls = [
            OutPutArgument(),
            SubjectArgument(),
        ]
        [cls(parser) for cls in args_cls]
        args = parser.parse_args(sys.argv[2:])

        results = []

        options = self.get_options(args)
        # first we try get rootCA,key, and rootCA.crt from User input, then from default dirs and only then
        # we create new one

        output = settings.CONFIG_DIR if not args.output else args.output
        try:
            root_key, root_cert = load_pem_private_key(args.rootKey), load_pem_x509_certificate(args.rootCertificate)
        except Exception as exc:
            logger.exception(exc)
            cert: bytes
            key: bytes

            cert, key = DomainSignedCertificate.create_root(output=output, options=options)

            root_key, root_cert = serialization.load_pem_private_key(key, password=None,
                                                                     backend=default_backend()), \
                                  x509.load_pem_x509_certificate(
                                      cert, default_backend()
                                  )

        for domain in args.domain:
            DomainSignedCertificate.create(
                domain,
                root_key,
                root_cert,
                output=output,
                options=options
            )
            cert_path, cert_key_path = os.path.join(output, f"{domain}.crt"), \
                                       os.path.join(output, f"{domain}.key")
            results.append(cert_path)
            results.append(cert_key_path)

        self.stdout(results)

    def command_root(self, parser: argparse.ArgumentParser = None):
        results = []
        args_cls = [
            OutPutArgument(),
            SubjectArgument(),
        ]
        [cls(parser) for cls in args_cls]

        args = parser.parse_args(sys.argv[2:])

        options = self.get_options(args)
        output = settings.CONFIG_DIR if not args.output else args.output

        DomainSignedCertificate.create_root(output=output, options=options)

        cert_path, cert_key_path = os.path.join(output, settings.DEFAULT_ROOT_CERT_NAME), \
                                   os.path.join(output, settings.DEFAULT_ROOT_KEY_NAME)
        results.append(cert_path)
        results.append(cert_key_path)

        self.stdout(results)

    def stdout(self, results: list):
        message = "\n".join(results)
        print(message)
