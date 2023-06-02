# Entropy Checker
### _File Entropy Analyzer_
entrocheck.py is a Python script for calulating and analyzing file entropy, for the purpose of determining if files or their segments are packed/encrypted/compressed or not.

Ultimately, the goal is for entrocheck.py to be able to calculate and analyze the entropy for both PE and ELF files and their segments.
## Usage
```
usage: entrocheck.py [-h] [-v] filepath

positional arguments:
  filepath       Path of file to calculate entropy for

optional arguments:
  -h, --help     show this help message and exit
  -v, --version  Show version number and exit

Examples:
	entrocheck.py ./susbinary
	entrocheck.py .\susbin.exe
```
**Example Output**
```
$ .\entrocheck.py .\susbin.dll 
File: .\susbin.dll 
Type: Windows PE
Total entropy: 6.3810486162173365
```

## Known Issues & TODO
- Detect 32/64 bit for Windows PE
- Determine segment offsets, calculate and analyze their entropy
- Add support for more file types/signatures
- Add option to submit multiple files at once
