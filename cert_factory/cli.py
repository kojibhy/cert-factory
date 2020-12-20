#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import List

from choices import NameOID_CHOICES
from signed import CertificateManager

logger = logging.getLogger('cert_factory')


class CommonArguments:
    def __call__(self, parser: argparse.ArgumentParser, *args, **kwargs):
        parser.add_argument(
            '--certificates-dir',
            help='',
        )


class DomainArgument:
    def __call__(self, parser: argparse.ArgumentParser, *args, **kwargs):
        parser.add_argument(
            '-d',
            '--domain',
            nargs='+',
            help='',
            required=True
        )
        parser.add_argument(
            '--rKey',
            default=None,
            help='',
        )
        parser.add_argument(
            '--rCert',
            default=None,
            help='',
        )


class NameOidArgument:
    def __call__(self, parser: argparse.ArgumentParser, *args, **kwargs):
        for name, value in NameOID_CHOICES.items():
            parser.add_argument(
                f'--{value}',
                default=None,
                required=False,
                help=f'{value}'
            )


class CliManager:
    usage = """
    ./cert_factory.py <command> [<args>] -h 
        The most commonly used commands are:
        - create
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

    @staticmethod
    def _init_parser(parser, klass: List):
        [cls(parser) for cls in [k() for k in klass]]
        return parser.parse_args(sys.argv[2:])

    @staticmethod
    def _create(**kwargs) -> List[str]:
        rkey_path = kwargs.pop("rKey", None)
        rcert_path = kwargs.pop("rCert", None)
        domains = kwargs.pop("domain", None)
        create_root_only = kwargs.pop("root_only", False)

        common_name = kwargs.get("commonName")
        if not common_name and create_root_only:
            kwargs["commonName"] = "DEMO-CERTIFICATE Root"

        manager = CertificateManager(
            certificates_dir=kwargs.pop("certificates_dir", None),
            options=kwargs,
        )
        if create_root_only:
            manager.create_root_pair(rkey_path, rcert_path)
        else:
            manager.save_and_sign(domains, rkey_path, rcert_path)
        return manager.messages

    def command_create(self, parser: argparse.ArgumentParser = None):
        args_classes = [
            CommonArguments,
            NameOidArgument,
        ]
        namespace: argparse.Namespace = self._init_parser(parser, args_classes)

        kwargs = {
            "root_only": True,
        }
        kwargs.update(vars(namespace))
        self.stdout(self._create(**kwargs))

    def command_sign(self, parser: argparse.ArgumentParser = None):
        args_classes = [
            CommonArguments,
            DomainArgument,
            NameOidArgument,
        ]
        namespace: argparse.Namespace = self._init_parser(parser, args_classes)

        self.stdout(self._create(**vars(namespace)))

    def stdout(self, messages: list):
        message = "\n".join(messages)
        print(message)
