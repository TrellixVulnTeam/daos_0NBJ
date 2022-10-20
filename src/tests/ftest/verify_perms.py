#!/usr/bin/env python3

import sys
import os
from argparse import ArgumentParser


class PermissionFailure(Exception):
    '''Base Exception class'''

def verify_r(path):
    assert os.access(path, os.R_OK)


def verify_w(path):
    assert os.access(path, os.W_OK)


def verify_x(path):
    assert os.access(path, os.X_OK)


def verify(paths, positive, negative):
    perms = parse_perm_str(positive, negative)
    for path in paths:
        for perm, expect_pass in perms.items():
            print(f'Verifying "{perm}" {"succeeds" if expect_pass else "fails"} on "{path}"')
            verify_fun = {
                'R': verify_r,
                'W': verify_w,
                'X': verify_x
            }.get(perm)
            try:
                verify_fun(path)
                if not expect_pass:
                    raise PermissionFailure(f'Expected "{perm}" to fail on "{path}"')
            except AssertionError as error:
                if expect_pass:
                    raise PermissionFailure(f'Expected "{perm}" to pass on "{path}"') from error


def parse_perm_str(positive, negative):
    perms = {}
    for perm in positive or []:
        if perm not in ('R', 'W', 'X'):
            raise ValueError(f'Permission "{perm}" unknown')
        perms[perm] = True
    for perm in negative or []:
        if perm not in ('R', 'W', 'X'):
            raise ValueError(f'Permission "{perm}" unknown')
        perms[perm] = False
    return perms


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "paths",
        action="append",
        type=str,
        help="path(s) to verify permissions of")
    parser.add_argument(
        '-p', '--positive',
        type=str,
        help='permissions in RWX that should succeed')
    parser.add_argument(
        '-n', '--negative',
        type=str,
        help='permissions in RWX that should fail')
    args = parser.parse_args()
    verify(args.paths, args.positive, args.negative)

    return 0


if __name__ == '__main__':
    sys.exit(main())
