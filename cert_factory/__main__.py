#!/usr/bin/env python3
import logging.config

if __name__ == '__main__':
    from cli import CliManager
    from default_settings import LOGGING_CONFIG

    cli = CliManager()
    # important to use __call__  for better test.
    logging.config.dictConfig(LOGGING_CONFIG)
    cli()
