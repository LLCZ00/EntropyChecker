#!/usr/bin/python3
#
# Copyright (C) 2022 LLCZ00
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.  
#

"""
Entropy Checker - Calculate a file's entropy

TODO:
    - Calculate entropy for individual segments, if applicable
"""

import argparse
import math
import sys
import os

_NAME = "entrocheck.py"
_VERSION = "v1.0.0"
_AUTHOR = "LCZ00"
_DESCRIPTION = f"""{_NAME} {_VERSION}, by {_AUTHOR}
CLI tool for calculating the entropy of files.
"""

"""
Argument Parsing
"""
class EntropyParser(argparse.ArgumentParser):
    """Override argparse class for better error handler"""
    def error(self, message="Unknown error", help=False):
        if help:
            self.print_help()
        else:
            print(f"Error. {message}")
            print(f"Try './{self.prog} --help' for more information.")
        sys.exit(1)


class ValidateFilepath(argparse.Action):
    """argparse Action to validate existence of process"""
    def __call__(self, parser, namespace, value, option_string=None):
        if not os.path.isfile(value):
            parser.error(f"Unable locate file '{value}'")

        setattr(namespace, self.dest, value)


def parseArguments():
    parser = EntropyParser(
    prog=_NAME,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=_DESCRIPTION,
    epilog=f"Examples:\n\t{_NAME} ./susbinary\n\t{_NAME} .\\susbin.exe"
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'{_NAME} {_VERSION}',
        help='Show version number and exit'
    )
    parser.add_argument(
        'filepath',
        action=ValidateFilepath,
        help="Path of file to calculate entropy for"
    )

    return parser.parse_args()

"""
Actual Entropy Calculation stuff
"""

def calculateEntropy(bytedata):
    totalsize = len(bytedata)
    bytecounts = [0 for _ in range(256)]
    for byte in bytedata:
        bytecounts[byte] += 1
    return -sum(map(lambda c: (c/totalsize) * math.log2(c/totalsize) if c != 0 else 0, bytecounts))

def winSegments(bytedata):
    print("[*] File type detected: Windows PE")
    # Finish finding segment offsets

def elfSegments(bytedata):
    e_phoff = 0x20
    if bytedata[4] == 1:
        print("[*] File type detected: ELF32")
        e_phoff = 0x1c
    elif bytedata[4] == 2:
        print("[*] File type detected: ELF64")
    # Finish finding segment offsets


def main():
    args = parseArguments()
    filebytes = None
    with open(args.filepath, "rb") as file:
        filebytes = file.read()
    
    if filebytes[:2] == b"MZ":
        winSegments(filebytes)
    elif filebytes[:4] == b"\x7fELF":
        elfSegments(filebytes)
    else:
        print("[*] Unknown file signature")

    print(f"Total entropy: {calculateEntropy(filebytes)}")


if __name__ == "__main__":
    sys.exit(main())
