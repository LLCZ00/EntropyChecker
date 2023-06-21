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
    - https://github.com/packing-box/bintropy
    - https://redirect.cs.umbc.edu/courses/graduate/CMSC691am/student%20talks/CMSC%20691%20Malware%20-%20Entropy%20Analysis%20Presentation.pdf
"""

import argparse
import math
import sys
import os

_NAME = "entrocheck.py"
_VERSION = "v2.0.0"
_AUTHOR = "LCZ00"
_DESCRIPTION = f"""{_NAME} {_VERSION}, by {_AUTHOR}
CLI tool for calculating the entropy of files and/or their segments.
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


class ValidateFilepaths(argparse.Action):
    """argparse Action to validate existence of process"""
    def __call__(self, parser, namespace, value, option_string=None):
        for path in value:
            if not os.path.isfile(path):
                parser.error(f"Invalid file '{path}'")
        setattr(namespace, self.dest, value)


def parseArguments():
    parser = EntropyParser(
    prog=_NAME,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=_DESCRIPTION,
    epilog=f"Examples:\n\t{_NAME} ./susbinary\n\t{_NAME} .\\susbin.exe\n\t{_NAME} ./susbinary ./susbin.exe ./sus32bin"
    )
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'{_NAME} {_VERSION}',
        help='Show version number and exit'
    )
    parser.add_argument(
        '--total',
        action='store_true',
        dest='onlytotal',
        help='Only calculate total entropy of file'
    )
    parser.add_argument(
        '--segments',
        action='store_true',
        dest='onlysegments',
        help='Only calculate entropy for file\'s segments (if applicable)'
    )
    parser.add_argument(
        'filepaths',
        nargs='+',
        action=ValidateFilepaths,
        help="Path of file(s) to analyze"
    )
    return parser.parse_args()


"""
Actual Entropy Calculation stuff
"""
class Entropy:
    def __init__(self, data):
        datasize = len(data)
        bytecounts = [0 for _ in range(256)]
        for byte in data:
            bytecounts[byte] += 1
        self.entropy = self.calculate(data)
        self.determination = self.analyze(self.entropy)

    def __str__(self):
        return f"{self.entropy:.3f} ({self.determination})"

    @staticmethod
    def calculate(bytedata):
        totalsize = len(bytedata)
        bytecounts = [0 for _ in range(256)]
        for byte in bytedata:
            bytecounts[byte] += 1
        return -sum(map(lambda c: (c/totalsize) * math.log2(c/totalsize) if c != 0 else 0, bytecounts))

    @staticmethod
    def analyze(entropy):
        if entropy <= 6.3:
            return "Not packed"
        elif 6.3 < entropy < 6.8:
            return "Possibly packed"
        else:
            return "Packed"


class GenericFile:
    """Generic/Base class
    """
    filetype = "Unknown"
    def __init__(self, filepath, filebytes):
        self.filepath = filepath
        self.filebytes = filebytes        

    def __str__(self):
        return f"File: {self.filepath} ({self.filetype})"

    def totalEntropy(self):
        print(f"Total entropy: {Entropy(self.filebytes)}")

    def segmentEntropy(self):
        return ""


class Elf(GenericFile):
    """Base Class for ELF binaries
    """
    endianness = "little"

    def __init__(self, filepath, filebytes):
        super().__init__(filepath, filebytes)
        if self.filebytes[5] == 2:
            self.endianness = "big"

    def parseSections(self):
        raise NotImplementedError

    def parseSegments(self):
        raise NotImplementedError

    def segmentEntropy(self):
        segments = self.parseSegments()
        if len(segments) == 0:
            return "No segments found"

        print("Segments:")
        for segment in segments:
            if segment["size"] == 0:
                continue
            entropy = Entropy(self.filebytes[segment['offset']:segment['offset']+segment['size']])
            print(f"{segment['name']} @{hex(segment['offset'])} - {entropy}")


class Elf64(Elf):
    filetype = "ELF64"

    def parseSections(self):
        e_shoff = int.from_bytes(self.filebytes[40:48], self.endianness) # Section header offset
        e_shnum = int.from_bytes(self.filebytes[60:62], self.endianness) # Number of section headers
        e_shentsize = int.from_bytes(self.filebytes[58:60], self.endianness) # Size of section header table entry

        sections = []
        return sections

    def parseSegments(self):
        e_phoff = int.from_bytes(self.filebytes[32:40], self.endianness) # Program header offset
        e_phnum = int.from_bytes(self.filebytes[56:58], self.endianness) # Number of program headers
        e_phentsize = int.from_bytes(self.filebytes[54:56], self.endianness) # Size of a program header table entry
        
        segments = []

        for _ in range(e_phnum):
            segment = {
            "name" : "",
            "offset":0,
            "size":0,
            }
            p_type = int.from_bytes(self.filebytes[e_phoff:e_phoff+4], self.endianness)
            if p_type == 1:
                segment["name"] = "LOAD"
                segment["offset"] = int.from_bytes(self.filebytes[e_phoff+8:e_phoff+16], self.endianness)
                segment["size"] = int.from_bytes(self.filebytes[e_phoff+32:e_phoff+40], self.endianness)
                segments.append(segment)

            e_phoff += e_phentsize

        return segments




class Elf32(Elf):
    filetype = "ELF32"

    def parseSections(self):
        sections = []
        return sections

    def parseSegments(self):
        segments = []
        return segments



class WinPE32(GenericFile):
    filetype = "PE32"


class WinPE64(GenericFile):
    filetype = "PE64"


def loadFile(filepath):
    """Class factory function, returns class determined by file signature
    """
    filebytes = None
    with open(filepath, "rb") as file:
        filebytes = file.read()

    if filebytes[:2] == b"MZ":
        return WinPE64(filepath, filebytes)
    elif filebytes[:5] == b"\x7fELF\x02":
        return Elf64(filepath, filebytes)
    elif filebytes[:5] == b"\x7fELF\x01":
        return Elf32(filepath, filebytes)
    else:
        return GenericFile(filepath, filebytes)


def main():
    args = parseArguments()

    for filepath in args.filepaths:
        file = loadFile(filepath)
        
        print(file)
        if not args.onlysegments:
            file.totalEntropy()

        if not args.onlytotal:
            file.segmentEntropy()

        print("")




if __name__ == "__main__":
    sys.exit(main())
