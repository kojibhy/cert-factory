#!/usr/bin/env python3
import logging.config
import os
import sys

try:
    assert sys.version_info >= (3, 8)
except AssertionError:
    sys.exit('Sorry. This script requires python3 >= 3.8 version')
WORK_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(WORK_DIR, 'cert_factory')
if not os.path.exists(BASE_DIR):
    raise Exception('Error, we could not find path with gateway: {0}!!'.format(BASE_DIR))
sys.path.append(BASE_DIR)

if __name__ == '__main__':
    from cli import CliManager
    from default_settings import LOGGING_CONFIG

    cli = CliManager()
    # important to use __call__  for better test.
    logging.config.dictConfig(LOGGING_CONFIG)
    cli()
