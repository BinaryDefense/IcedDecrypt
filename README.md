# IcedDecrypt
IcedID Decryption Tool


IceDecrypt is a bulk IcedID decryption tool allowing for decryption/payload reassembly for the new license.dat payload drop, along with gziploader payload decryption, and bot config extraction for icedid downloaders (less likely to work due to method of extraction + iced's own defenses).

# Required Libs
pefile
argparse

# Usage
python3 IcedDecrypt.py -f <input file> -o <optional file output>


