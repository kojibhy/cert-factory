#!/usr/bin/env python3
from arguments import Args

if __name__ == '__main__':
    cli = Args()
    # important to use __call__  for better test.
    cli()
