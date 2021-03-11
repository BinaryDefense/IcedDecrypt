import struct
import sys
import re
import base64
import pefile

import time

class PEGen:
    def __init__(self,machType,data,dataDict):
        self.Reserved = b"\x00\x00\x00\x00"
        self.PEMag = b"\x50\x45\x00\x00"
        if machType == 0:
            self.PEMach = b"\x4c\x01"
        elif machType == 1:
            self.PEMach = b"\x64\x86"
        self.data = data
        self.dataDict = dataDict

    def genMZ(self):
        self.MZHead = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21\x54\x68\x69\x73\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\x63\x61\x6e\x6e\x6f\x74\x20\x62\x65\x20\x72\x75\x6e\x20\x69\x6e\x20\x44\x4f\x53\x20\x6d\x6f\x64\x65\x2e\x0d\x0d\x0a\x24\x00\x00\x00\x00\x00\x00\x00\x59\x78\x8a\xea\x1d\x19\xe4\xb9\x1d\x19\xe4\xb9\x1d\x19\xe4\xb9\x3a\xdf\x9f\xb9\x1f\x19\xe4\xb9\x6e\x7b\xe5\xb8\x16\x19\xe4\xb9\x1d\x19\xe5\xb9\x07\x19\xe4\xb9\xfb\x7d\xe0\xb8\x18\x19\xe4\xb9\xfb\x7d\xe4\xb8\x1c\x19\xe4\xb9\xfb\x7d\xe6\xb8\x1c\x19\xe4\xb9\x52\x69\x63\x68\x1d\x19\xe4\xb9\x00\x00\x00\x00\x00\x00\x00\x00" #MZ header can be relatively static
        return 1

    def genPE(self):
        PESecCo = len(self.dataDict["Segments"]).to_bytes(2,byteorder = "little")
        PETime = int(time.time()).to_bytes(4,byteorder = "little")
        PERest = b"\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00\x22\x20"
        self.PEHead = self.PEMag + self.PEMach + PESecCo + PETime + PERest
        return 1

    def genOptional(self):
        OPMag = b"\x0B\x02"
        OPLinker = b"\x0E\x0C"
        for segm in self.dataDict["Segments"]: #identifies the 3 important segments needed for proper iced reassembly

            if segm["VirtualSegmentOffset"] == 0x1000:
                self.OPCodeSize = segm["SegmentSize"].to_bytes(4,byteorder = "little")
                self.textSegSize = segm["SegmentSize"]
                self.OPAddress = segm["VirtualSegmentOffset"].to_bytes(4,byteorder = "little")

            elif segm["VirtualSegmentOffset"] == 0x20000:
                self.relocSectionSize = segm["SegmentSize"].to_bytes(4,byteorder = "little")
                self.relocAddress = segm["VirtualSegmentOffset"].to_bytes(4,byteorder = "little")
            elif segm["VirtualSegmentOffset"] == 0x27000:
                self.dataAddress = segm["VirtualSegmentOffset"].to_bytes(4,byteorder = "little")
                self.dataSectionSize = segm["SegmentSize"].to_bytes(4,byteorder = "little")





        OPOtherSizes = b"\x00\x08\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00"
        OPBase = self.OPAddress
        OPAddressPattern = rb"\x48\x83\xec\x28\xe8....\x85" #Dynamically find the entrypoint using regex
        m = re.search(OPAddressPattern, self.data,re.DOTALL)
        if m:
            self.OPAddress1 = m.start().to_bytes(4,byteorder="little")

        self.OPHead = OPMag + OPLinker + OPOtherSizes + self.OPAddress1 + OPBase
        return 1

    def genOpImageBase(self): #generate the imageBase
        ImagBase = self.dataDict["ImageBase"].to_bytes(8,byteorder="little")
        SectionAlignment = b"\x00\x10\x00\x00"
        FileAlignment = b"\x00\x02\x00\x00"
        ImagOS = b"\x06\x00\x00\x00"
        ImagVer = b"\x00\x00\x00\x00"
        ImagMajSubVer = b"\x06\x00\x00\x00"
        ImagRes = self.Reserved
        ImagSize = (self.dataDict["SizeOfImage"]).to_bytes(4,byteorder="little")
        ImagHeadSize = b"\x00\x10\x00\x00"
        CheckSum = b"\x3F\xA8\x2F\x00"
        ImagSubSys = b"\x02\x00"
        ImagDllCharacts = b"\x60\x00"
        ImagSHRes = 0x100000.to_bytes(8,byteorder="little")
        ImagSCommit = 0x1000.to_bytes(8,byteorder="little")
        ImagHeapRes = 0x100000.to_bytes(8,byteorder="little")
        ImagHeapCom = 0x1000.to_bytes(8,byteorder="little")
        ImagLFlags = self.Reserved
        ImagNoRVASize = 0x10.to_bytes(4,byteorder = "little")
        self.OPImagBase = ImagBase + SectionAlignment + FileAlignment + ImagOS + ImagVer + ImagMajSubVer + ImagRes + ImagSize + ImagHeadSize + CheckSum + ImagSubSys + ImagDllCharacts + ImagSHRes + ImagSCommit + ImagHeapRes + ImagHeapCom + ImagLFlags + ImagNoRVASize
        return 1

    def genOpImageFull(self):
        self.genOptional()
        self.genOpImageBase()
        self.FullOpHeader = self.OPHead + self.OPImagBase
        return 1

    def genTables(self):
        exportTable = self.Reserved #TODO: Find export table
        exportTableSize = self.Reserved

        ImportTable_1 = self.dataDict["ImportTableOffset"].to_bytes(4,byteorder="little")
        ImportTableSize_1 = self.dataDict["ImportTableSize"].to_bytes(4,byteorder="little")

        ExceptionDir = self.Reserved
        ExceptDirSize = self.Reserved
        ExceptDirSec = self.Reserved[:2]

        BaseReloc = self.Reserved
        BaseRelocSize = self.Reserved
        BaseRelocRest = b"\x00" * 48

        ImportAddr = self.Reserved
        ImportAddrSize = self.Reserved
        ImportAddrRest = b"\x00" * 24



        ImageSectionHeader = b".text\x00\x00\x00"
        ImageSectionSize = self.textSegSize.to_bytes(4,byteorder="little")
        ImageSectionAddr = self.OPAddress
        ImageSectionRSize = self.OPCodeSize
        ImageSectionPtr = self.OPAddress
        ImageSectionRest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60"

        RelocSectionHeader = b".relocs\x00"
        RelocSectionSize = self.relocSectionSize
        RelocSectionAddr = self.relocAddress
        RelocSectionRSize = self.relocSectionSize
        RelocSectionPtr = self.relocAddress
        RelocSectionRest = ImageSectionRest

        DataSectionHeader = b".data\x00"
        DataSectionSize = self.dataSectionSize
        DataSectionAddr = self.dataAddress
        DataSectionRSize = self.dataSectionSize
        DataSectionPtr = self.dataAddress
        DataSectionRest = ImageSectionRest

        print(f"[+] Generated .text Section\n\tImage Section Address: {int.from_bytes(ImageSectionAddr,byteorder='little')}\n\tImage Size: {int.from_bytes(ImageSectionSize,byteorder='little')}")
        print(f"[+] Generated .relocs Section\n\tImage Section Address: {int.from_bytes(RelocSectionAddr,byteorder='little')}\n\tImage Size: {int.from_bytes(RelocSectionSize,byteorder='little')}")
        print(f"[+] Generated .data Section\n\tImage Section Address: {int.from_bytes(DataSectionAddr,byteorder='little')}\n\tImage Size: {int.from_bytes(DataSectionSize,byteorder='little')}")
        segmList = [b".rdata",b".data"]

        i = 2
        self.segmData = ImageSectionHeader + ImageSectionSize + ImageSectionAddr + ImageSectionRSize + ImageSectionPtr + ImageSectionRest
        self.segmData += RelocSectionHeader + RelocSectionSize + RelocSectionAddr + RelocSectionRSize + RelocSectionPtr + RelocSectionRest
        for segm in self.dataDict["Segments"]:
            if i == 2:
                ImportTable = segm["VirtualSegmentOffset"].to_bytes(4,byteorder = "little")
                ImportTableSize = segm["SegmentSize"].to_bytes(4,byteorder="little")
                ImportTableSize += b"\x00" * 8


            if segm["VirtualSegmentOffset"] == 0x1000 or segm["VirtualSegmentOffset"] == 0x20000:
                continue
            segmNameIndex = segm["SegmentIndex"] % len(segmList)
            segmNameCounter = int(segm["SegmentIndex"] / len(segmList))
            if segmNameCounter != 0:
                segmName = segmList[segmNameIndex] + str(segmNameCounter).encode()
            else:
                segmName = segmList[segmNameIndex]
            segmName = segmName + ((8 - len(segmName)) * b"\x00")
            segmVirtSize = segm["SegmentSize"].to_bytes(4,byteorder="little")
            segmVirtAddr = segm["VirtualSegmentOffset"].to_bytes(4,byteorder = "little")
            segmRawSize = segmVirtSize
            segmPtr = segmVirtAddr
            i += 1
            segmRest = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x60"
            self.segmData += segmName + segmVirtSize + segmVirtAddr + segmRawSize + segmPtr + segmRest

        TablesAll = b"\xFF\xFF\xFF\xFF\x61\x00\x00\x00\x48\x49\x02\x00\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x05\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x49\x02\x00\x50\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.genExportTable()

        TablesAll = TablesAll.replace(b"\x48\x49\x02\x00",ImportTable_1)
        TablesAll = TablesAll.replace(b"\xEC\x00\x00\x00",ImportTableSize_1)
        self.TablesAll = TablesAll.replace(b"\xFF\xFF\xFF\xFF",self.ExportOff)

        return 1

    def genExportTable(self): #generate export table
        offset = int.from_bytes(self.dataAddress,byteorder="little") + 0x1100
        self.offset = offset
        Timestamp = int(time.time()).to_bytes(4,byteorder = "little")
        MajVer = b"\x00\x00"
        MinVer = b"\x00\x00"
        ordBase = b"\x01\x00\x00\x00"
        cAddrTable =  b"\x01\x00\x00\x00"
        cNamePtr  = b"\x01\x00\x00\x00"
        ExportAddressTbl = (offset + 40).to_bytes(4,byteorder = "little")
        ExportOrdTbl = (offset + 48).to_bytes(4,byteorder = "little")
        ExportNameTbl = (offset + 52).to_bytes(4,byteorder = "little")
        ExportDllOff = (offset + 0x4A).to_bytes(4,byteorder = "little")
        self.exportTable = self.Reserved+Timestamp+MajVer+MinVer+ExportDllOff + ordBase+cAddrTable+cNamePtr + ExportAddressTbl + ExportNameTbl + ExportOrdTbl


        dllRva = self.OPAddress1
        forwardRva = self.OPAddress1

        ordinal = b"\x01\x00\x00\x00"
        self.exportTable = self.exportTable + dllRva + forwardRva + ordinal

        lpExportName = (offset + len(self.exportTable)+4).to_bytes(4,byteorder="little")
        ExportName = b"DllRegisterServer\x00"
        DllExportName = b"fixed_loader64.dll\x00"
        ExportDllOff = (offset + 4 + len(self.exportTable) + len(ExportName)).to_bytes(4,byteorder="little")
        self.exportTable = self.Reserved+Timestamp+MajVer+MinVer+lpExportName + ordBase+cAddrTable+cNamePtr + ExportAddressTbl + ExportNameTbl + ExportOrdTbl
        self.exportTable = self.exportTable + dllRva + forwardRva + ordinal
        self.exportTable = self.exportTable + ExportDllOff + ExportName + DllExportName

        self.ExportOff = offset.to_bytes(4,byteorder="little")


    def genExecutable(self): #generate icedid exe
        self.genMZ()
        self.genPE()
        self.genOpImageFull()
        self.genTables()

        MZHeader_Part = self.MZHead + self.PEHead + self.FullOpHeader + self.TablesAll + self.segmData
        necNulls = 0x1000 - len(MZHeader_Part)

        self.MZHeader_Full = MZHeader_Part + (b"\x00" * necNulls)
        outdata = self.MZHeader_Full + self.data[0x1000:self.offset] + self.exportTable + self.data[self.offset + len(self.exportTable):]
        return outdata
