import argparse
import base64
import binascii
import collections
import hashlib
import math
import os
import re
import struct
import time

import pefile

import PeGen

rol = lambda val, r_bits, max_bits: \
    (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
    ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))  # rol lambda func. python pls add

ror = lambda val, r_bits, max_bits: \
    ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
    (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))  # ror lambda func. python pls add


def entropy(data):
    e = 0
    counter = collections.Counter(data)
    data_len = len(data)
    for count in counter.values():
        p_x = count / data_len
        e += - p_x * math.log2(p_x)
    return e


class IcedDecrypt:
    def __init__(self, filename, output):
        self.filename = filename
        self.output = output

    def main(self):
        filein = open(self.filename, "rb")
        data = filein.read()
        filein.close()

        pe, isPe = self.detectPE(self.filename)  # Detect PE file using pefile
        if isPe:
            print("[+] Warning: Not Guaranteed to work")
            dll_data = open(self.filename, "rb").read()
            c2BuffDict = {"C2Buff": b"", "Size": 0}
            c2BuffDict = self.extractC2Buff(c2BuffDict, dll_data)

            decDict = self.decryptWrapper(c2BuffDict)
            print("[+] Finished Decrypting And Extracting Data")
            outDict = self.parseC2Buffer(decDict)
            filename1 = f"out_{hashlib.md5(dll_data).hexdigest()}_{int(time.time())}_output"
            try:
                os.mkdir("Logs")
            except Exception as e:
                print(e)

            outfile = open(f"Logs/{filename1}.txt", "w+")
            outfile.write(str(outDict))
            outfile.close()
        elif data[:2] == b"\x1F\x8B":  # If Detect gzip header
            print("[+] Identified GZIPLoader")
            parsedData, key = self.parseGZIPLoader(data)  # Parse Gzip File and extract data and key
            outdata = self.decrypt(parsedData, size=len(data) - 0x20, key=key)
            print("[+] Finished Decrypting Data")
            parsedDict = self.parseDec_GZIPLoader(outdata)
            self.genDropFiles(parsedDict)
            print("[+] Finished Extracting Drop Files")

            outDict = {"key": base64.b64encode(key).decode(), "size": len(data) - 20}

        else:  # .dat file decryption attempt
            key = data[-0x10:]  # license.dat key offset = last 16 bytes of data
            print("[+] decryption key for dat file: %s" % binascii.hexlify(key).decode("utf-8"))
            outdata = self.decrypt(data, size=len(data) - 20, key=key)
            print("[+] entropy check: %s" % entropy(outdata))
            print("[+] Finished Decrypting Data")
            try:
                os.mkdir("Assembled_Payloads_Debug")
            except Exception as e:
                print(e)

            try:
                os.mkdir("Assembled_Payloads")
            except Exception as e:
                print(e)

            filename = f"out_{hashlib.md5(outdata).hexdigest()}_{int(time.time())}"
            print("[+] output file for decrypted .dat file: %s" % filename)
            outfile = open(f"Assembled_Payloads_Debug/{filename}.file", "wb")
            outfile.write(outdata)
            outfile.close()
            outDict = {"key": base64.b64encode(key).decode(), "size": len(data) - 20}

            parsedData, parsedDict = self.ParseData(outdata)
            pe_gen = PeGen.PEGen(1, parsedData, parsedDict)  # Supply ParsedData and ParsedDict, arg1 = machType (0,1)

            fixed = pe_gen.genExecutable()
            outfile = open(f"Assembled_Payloads/{filename}_fixed_dll.file", "w+b")
            outfile.write(fixed)
            outfile.close()

            try:
                os.mkdir("Logs")
            except Exception as e:
                print(e)

            outfile = open(f"Logs/{filename}.txt", "w+")
            outfile.write(str(parsedDict))
            outfile.close()

    def parseC2Buffer(self, dataDict):  # read values from 0xA9 bytes large data block
        data = base64.b64decode(dataDict["Decrypted_Data"])
        buildID = int.from_bytes(data[:4], byteorder="little")
        uriLen = int.from_bytes(data[4:8], byteorder="little")
        uri = data[8:8 + uriLen]
        counter = 8 + uriLen

        count2 = self.incNulls(data[counter:])
        counter = counter + count2
        strLen = data[counter]
        c2_1 = data[counter:strLen + counter]
        counter += strLen
        strLen = data[counter]
        c2_2 = data[counter:strLen + counter]
        unkData = data[-0x14:]
        outDict = {"BuildID": buildID, "uri": uri.decode(), "c2_1": c2_1[1:-1].decode(), "c2_2": c2_2[1:-1].decode(),
                   "UnknownData": base64.b64encode(unkData).decode()}
        return outDict

    def ParseData(self, data):
        buffer = data[0x81:]
        """Struct payload_segment_config {
                qword ImageBase;
                dword ImageVirtualSize;
                dword ImageEntryPoint;
                dword Import Table Offset;
                dword Import table Virtual Offset;
                dword Import Table Size;
            }
"""

        dataSizeTemp = int.from_bytes(buffer[0x8:0xC], byteorder="little")

        outBuffer = b"\x00" * int(0x1000 * (round(dataSizeTemp / 0x1000)))
        dataSegments = int.from_bytes(buffer[0x1c:0x20], byteorder="little")
        imagBase = int.from_bytes(buffer[:0x8], byteorder="little")

        imagSize = int.from_bytes(buffer[0x8:0xC], byteorder="little")
        imagEntry = int.from_bytes(buffer[0xC:0x10], byteorder="little")
        impTableOff = int.from_bytes(buffer[0x10:0x14], byteorder="little")
        impTableVirtOff = int.from_bytes(buffer[0x14:0x18], byteorder="little")
        impTableSize = int.from_bytes(buffer[0x18:0x1C], byteorder="little")

        tempOut = b""
        print(dataSegments)
        segDict = {"SegmentIndex": 0, "SegmentSize": 0, "RawSegmentOffset": 0,
                   "VirtualSegmentOffset": 0}  # Initialize dicts for unpacking values
        bigDict = {"Segments": [], "ImageBase": imagBase, "ImageSize": imagSize, "ImageBaseEntry": imagEntry,
                   "ImportTableOffset": impTableOff, "ImportTableSize": impTableSize}

        print(bigDict)

        totalSize = 0
        for i in range(dataSegments):
            """Source: malwarebytes analysis of iced
                struct section {
                    dword VA;
                    dword Virtual_Size
                    dword raw_offset
                    dword raw_size
                    byte access
                }"""

            x = i * 0x11  # each buffer is 0x11 bytes large, with the first header being 0x20 bytes large
            dataOff = int.from_bytes(buffer[0x28 + x:0x2c + x], byteorder="little")
            dataSize = int.from_bytes(buffer[0x2C + x:0x30 + x], byteorder="little")
            virtualOffset = int.from_bytes(buffer[0x20 + x:0x24 + x], byteorder="little")

            print(f"[+] Data Segment Size {hex(dataSize)}")
            print(f"[+] Data Offset {hex(dataOff)}")
            print(f"[+] Virtual Offset: {hex(virtualOffset)}")
            segDict["SegmentIndex"] = i
            segDict["SegmentSize"] = dataSize
            segDict["RawSegmentOffset"] = dataOff
            segDict["VirtualSegmentOffset"] = virtualOffset
            bigDict["Segments"].append(segDict)
            segDict = {"SegmentIndex": 0, "SegmentSize": 0, "RawSegmentOffset": 0,
                       "VirtualSegmentOffset": 0}  # zero dict
            totalSize = int(0x1000 * (round((totalSize + dataSize) / 0x1000)))

            tempOut = outBuffer[:virtualOffset] + buffer[dataOff:dataOff + dataSize] + outBuffer[
                                                                                       virtualOffset + dataSize:]
            outBuffer = tempOut
        bigDict["SizeOfImage"] = totalSize + 0x1000
        return outBuffer, bigDict

    def fixKey(self, key, x, y):
        tempKey = b""
        tempVal = key[y:y + 4]
        tempVal = int.from_bytes(tempVal, byteorder="little")  # First grab from y
        rotVal = (tempVal & 7) & 0xFF
        tempVal = key[x:x + 4]  # then grab from x
        tempVal = int.from_bytes(tempVal, byteorder="little")
        tempVal = ror(tempVal, rotVal, 32)
        tempVal += 1
        tempValX = tempVal.to_bytes(4, byteorder="little")  # save to storage var
        rotVal = (tempVal & 7) & 0xFF  # Gen rotVal

        tempVal = key[y:y + 4]  # then grab from y (again)
        tempVal = int.from_bytes(tempVal, byteorder="little")
        tempVal = ror(tempVal, rotVal, 32)
        tempVal += 1
        tempValY = tempVal.to_bytes(4, byteorder="little")

        # fix Key
        tempKey = key[:x] + tempValX + key[x + 4:]
        tempKey = tempKey[:y] + tempValY + tempKey[y + 4:]

        return tempKey

    def decrypt(self, data, size, key):
        outList = []
        if size > 400:
            print(f"[+] Size of data: {len(data)}")
            print(f"[+] Size: {size}")
        for i in range(size):
            x = (i & 3)
            y = ((i + 1) & 3)

            c = key[y * 4] + key[x * 4]
            c = (c ^ data[i]) & 0xFF

            outList.append(c.to_bytes(1, byteorder="little"))

            key = self.fixKey(key, x * 4, y * 4)

        return b''.join(outList)

    def extractC2Buff(self, outdict, data):
        pe = pefile.PE(data=data)

        for section in pe.sections:
            if b".data" in section.Name:
                RVA_Base = section.PointerToRawData
                if RVA_Base == 0x0:
                    RVA_Base = section.VirtualAddress

                break
        C2BuffOffset = RVA_Base
        C2BuffSize = rb"\x66\xC7.....\x48\xC7.....(....)[\xFF\xE8]"  # Use Regex to find C2 Buffer in exe
        dataSizeMatch = re.search(C2BuffSize, data, re.DOTALL)

        if dataSizeMatch:
            dataSize = struct.unpack("<L", dataSizeMatch.group(1))[0]
        else:
            print("[!] Encrypted Data Size Not Found")

            dataSize = 0x25C
        outdict["Size"] = dataSize
        outdict["C2Buff"] = data[C2BuffOffset:C2BuffOffset + dataSize]
        return outdict

    def decryptWrapper(self, inDict):
        outdict = {"Decrypted_Data": ""}  # decrypt C2 Buffer
        data = inDict["C2Buff"]
        size = inDict["Size"]
        key = data[-0x10:]

        outdata = self.decrypt(data, size=size, key=key)
        outb64 = base64.b64encode(outdata)
        try:
            outb64 = outb64.decode()
        except Exception as e:
            outb64 = outb64
        outdict["Decrypted_Data"] = outb64
        return outdict

    def detectPE(self, filename):
        try:
            pe = pefile.PE(filename)  # attempt pefile load pe file
            return pe, 1
        except Exception as e:
            return None, 0

    def bruteforceKey(self, data, buffsize=0x100):
        data_part = data[:buffsize]  # Grab part of the data so we don't need to bruteforce 5MB
        tempData = data_part  # tempData holder
        i = 0

        while tempData[0x20:0x24] != b"\x00\x00\x00\x00":
            key = data[-0x20 + i:-0x10 + i]

            tempData = self.decrypt(data_part, size=len(data_part), key=key)
            i += 1
            if b"\x00\x00\x00\x00" in tempData:
                print(tempData)

        return key

    def parseGZIPLoader(self, data):
        '''Gzip Data format
        first 10 bytes: 1f8b0808000000000000;
        CSTR Filename;
        buffer DATA;
        ...
        buffer Key = data[(dataStart + 0x0A + len(FileName) + 1) + (dataSize -0x1E - (len(FileName) + 1))):(dataStart + 0x0A + len(FileName) + 1) + (dataSize -0x1E - (len(FileName) + 1))) + 0x10];'''

        dataHeader = data[:0x0A]
        filename = b""
        i = 0
        while data[0x0A + i] != 0x00:
            filename += data[0x0A + i].to_bytes(1, byteorder="little")
            i += 1

        i += 1
        filename += b"\x00"
        dataSize = len(data)
        print("[+] Found Data Start. Attempting Key Bruteforce...")

        key = self.bruteforceKey(
            data[0xA + len(filename):])  # Using extracted data, bruteforce the key using a select batch of keys
        print(f"[+] Identified Key: {key}")
        return data[0xA + len(filename):], key

    def extractStrFromBuff(self, data):
        string1 = b""

        for i in range(len(data)):
            if data[i] == 0x00:
                break
            string1 += data[i].to_bytes(1, byteorder="little")
        return string1

    def incNulls(self, data):
        i = 0
        while data[i] == 0x00:
            i += 1
        return i

    def parseDec_GZIPLoader(self, data):  # Once gziploader is decrypted, parse the 0xA9 byte config
        """
        Struct gziploader_payload_config {
                Byte hardcoded2Val;
                Byte Flag;
                Dword sizeOfDatfile;
                Dword sizeOfDllFile;
                Cstr DatFileDir;
                Buffer[0x14] Reserved;
                Cstr DatFileName;
                Buffer[0x13] Reserved;
                Cstr DllFileName;
                Buffer[0x12] Reserved;
            }
        """
        hardcoded_val = data[0:1]
        flag = data[1:2]
        datfile_size = int.from_bytes(data[2:6], byteorder="little")
        print("[+] datfile size: ", datfile_size)
        dllfile_size = int.from_bytes(data[6:10], byteorder="little")
        print("[+] dllfile size: ", dllfile_size)
        dirname = self.extractStrFromBuff(data[10:])
        print("[+] Directory Name:", dirname)

        count = self.incNulls(data[10 + len(dirname):])
        datname = self.extractStrFromBuff(data[count + 10 + len(dirname):])
        print("[+] Dat Name :", datname)

        count = count + 10 + len(dirname) + len(datname)
        datname = datname[1:]
        count2 = self.incNulls(data[count:])
        count = count + count2
        dllname = self.extractStrFromBuff(data[count:])
        print("[+] Dll Name: ", dllname)
        count += len(dllname)
        count2 = self.incNulls(data[count:])
        count += count2
        # datfile offset is now 710 bytes in
        datfile_data = data[710:710 + datfile_size]
        dllfile_start = 710 + datfile_size
        dllfile_data = data[dllfile_start:dllfile_start + dllfile_size]
        datfile_b64 = base64.b64encode(datfile_data).decode()
        dllfile_b64 = base64.b64encode(dllfile_data).decode()
        ParsedDict = {"Directory_Name": dirname.decode(),
                      "DatFile_Name": datname.decode(),
                      "DllFile_Name": dllname.decode(),
                      "DatFile": datfile_b64,
                      "DllFile": dllfile_b64}

        return ParsedDict

    def genDropFiles(self, data_dict):  # Generate files to write
        try:
            os.mkdir("Payloads")
        except Exception as e:
            print(e)
        try:
            os.mkdir(f"Payloads/{data_dict['Directory_Name']}")
        except Exception as e:
            print(e)
        datFileOut = f"Payloads/{data_dict['Directory_Name']}/{data_dict['DatFile_Name']}"
        dllFileOut = f"Payloads/{data_dict['Directory_Name']}/{data_dict['DllFile_Name']}"
        print("[+] output of dll file location: %s" % dllFileOut)
        # rundll string not included anymore
        # rundllOut = f"Payloads/{data_dict['Directory_Name']}/Rundll32Execution.txt"
        datFileData = base64.b64decode(data_dict["DatFile"])
        dllFileData = base64.b64decode(data_dict["DllFile"])
        datout = open(datFileOut, "w+b")
        datout.write(datFileData)
        datout.close()
        dllout = open(dllFileOut, "w+b")
        dllout.write(dllFileData)
        dllout.close()
        rundllstr = 'rundll32.exe "{}",update /i:"{}"'
        rundllstr = rundllstr.format(f"%localappdata%/{dataDict['DllFile_Name']}",f"{dataDict['Directory_Name']}/{dataDict['DatFile_Name']}")

        print("Rundll32 String: ",rundllstr)
        rundll  = open(rundllOut,"w+b")
        rundll.write(f"copy {dataDict['DllFile_Name']} C:\\Users\\admin\\Appdata\\Local\\".encode() + b"\r\n")
        rundll.write(f"md C:\\Users\\admin\\Appdata\\Roaming\\{dataDict['Directory_Name']}\\".encode() + b"\r\n")
        rundll.write(f"copy {dataDict['DatFile_Name']} C:\\Users\\admin\\Appdata\\Roaming\\{dataDict['Directory_Name']}\\".encode() + b"\r\n")
        rundll.write(rundllstr.encode() + b"\r\n")
        rundll.close()
        print(f"[+] Wrote {datFileOut}, {dllFileOut}, and {rundllOut}")
        
        try:
            print("[+] Attempting C2 Buffer Decryption")
            iced2 = IcedDecrypt(filename=dllFileOut, output=f"{dllFileOut}_output.file")
            iced2.main()
        except Exception as e:
            print(e)

        return


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', help="Input Filename", required=True)
    parser.add_argument('-o', '--output', help="Output Filename", required=False, default="output")
    args = parser.parse_args()
    icedDec = IcedDecrypt(filename=args.filename, output=args.output)
    icedDec.main()
