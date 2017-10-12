##credit to https://bitbucket.org/!api/2.0/snippets/Alexander_Hanel/onboA/b4246411adbaa2ca5eda573925381d2d337546a2/files/decoder.py

import base64
import sys
import re
import gzip
import StringIO
import hexdump as h
from capstone import *


def find_base64(str_data):
    # most base64 regex patterns are too strict. This patter returns non-base64 patterns
    pattern = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    found = re.findall(pattern, str_data)
    #
    if found:
        # assumes the largest based64 is valid.
        return max(found, key=len)
    else:
        return ""


def decode_base64(test_data):
    """decode base64 data"""
    try:
        temp = base64.b64decode(test_data)
        return (True, temp)
    except:
        return (False,"")


def decompress_gzip(data):
    """decompress gzip data"""
    try:
        temp = StringIO.StringIO(data)
        decompressedFile = gzip.GzipFile(fileobj=temp)
        return (True, decompressedFile.read())
    except:
        return (False, None)


def disassemble(code):
    """prints assembly using capstone engine"""
    print "\nPosible Shellcode 32-bit"
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(code, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    print "\nPosible Shellcode 64-bit"
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, 0x1000):
        print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))


def write_file(data, name):
    """write file"""
    with open(name, "wb") as out:
        out.write(data)


def run():
    f = open(sys.argv[1], "rb")
    _input = f.read()
    # carveout base64 from powershell
    found_base64 = find_base64(_input)
    # decode base64
    status, decoded_base64 = decode_base64(found_base64)
    if status:
        print "\nBase64 Data:"
        print found_base64
        # decompress Gzip
        status, decompressed = decompress_gzip(decoded_base64)
        if status:
            print "\nDecompressed PowerShell Script:"
            print decompressed
            # write decompressed powershell script
            write_file(decompressed, f.name + ".ps.txt")
            found_base64 = find_base64(decompressed)
            status, decoded_base64 = decode_base64(found_base64)
            if status:
                # decoded_base64 is the shellcode
                write_file(decoded_base64, f.name + ".bin")
                print "\nHex dump of decoded base64 Shellcode"
                h.hexdump(decoded_base64)
                disassemble(decoded_base64)


run()
