import uuid
import io
from construct import Struct, Int16ul, GreedyRange, Bytes, StringEncoded, this, Int32ul, If, Enum, CString, IfThenElse, BitsSwapped, BitStruct, Flag, Int32sl, Int8ul

from strelka import strelka

class ScanLNK(strelka.Scanner):
    #Collects metadata from lnk files.

    def scan(self, data, file, options, expire_at):
        with io.BytesIO(data) as lnk_io:
            lnk_data = lnk_io.read()

        UnicodeString = "UnicodeString" / Struct(
                "Length" / Int32ul,
                "Characters" / StringEncoded(Bytes(this.Length * 2), "utf16")
        )

        LinkTargetIDList = "LinkTargetIDList" / Struct(
            "IDListSize" / Int16ul,
            "ItemID" / GreedyRange(Struct(
                "ItemIDSize" / Int16ul,
                "Data" / Bytes(this.ItemIDSize - 2),
            )),
            "TerminalID" / Int16ul
        )

        TypedPropertyValue = "TypedPropertyValue" / Struct(
            "Type" / Enum(Int16ul,
                VT_EMPTY=0x0000,
                VT_NULL=0x0001,
                VT_I2=0x0002,
                VT_I4=0x0003,
                VT_R4=0x0004,
                VT_R8=0x0005,
                VT_CY=0x0006,
                VT_DATE=0x0007,
                VT_BSTR=0x0008,
                VT_ERROR=0x000A,
                VT_BOOL=0x000B,
                VT_DECIMAL=0x000E,
                VT_I1=0x0010,
                VT_UI1=0x0011,
                VT_UI2=0x0012,
                VT_UI4=0x0013,
                VT_I8=0x0014,
                VT_UI8=0x0015,
                VT_INT=0x0016,
                VT_UINT=0x0017,
                VT_LPSTR=0x001E,
                VT_LPWSTR=0x001F,
                VT_FILETIME=0x0040,
                VT_BLOB=0x0041,
                VT_STREAM=0x0042,
                VT_STORAGE=0x0043,
                VT_STREAMED_Object=0x0044,
                VT_STORED_Object=0x0045,
                VT_BLOB_Object=0x0046,
                VT_CF=0x0047,
                VT_CLSID=0x0048,
                VT_VERSIONED_STREAM=0x0049,
                VT_I2_2=0x1002,
                VT_I4_2=0x1003,
                VT_R4_2=0x1004,
                VT_R8_2=0x1005,
                VT_CY_2=0x1006,
                VT_DATE_2=0x1007,
                VT_BSTR_2=0x1008,
                VT_ERROR_2=0x100A,
                VT_BOOL_2=0x100B,
                VT_VARIANT_2=0x100C,
                VT_I1_2=0x1010,
                VT_UI1_2=0x1011,
                VT_UI2_2=0x1012,
                VT_UI4_2=0x1013,
                VT_I8_2=0x1014,
                VT_UI8_2=0x1015,
                VT_LPSTR_2=0x101E,
                VT_LPWSTR_2=0x101F,
                VT_FILETIME_2=0x1040,
                VT_CF_2=0x1047,
                VT_CLSID_2=0x1048,
                VT_I2_3=0x2002,
                VT_I4_3=0x2003,
                VT_R4_3=0x2004,
                VT_R8_3=0x2005,
                VT_CY_3=0x2006,
                VT_DATE_3=0x2007,
                VT_BSTR_3=0x2008,
                VT_ERROR_3=0x200A,
                VT_BOOL_3=0x200B,
                VT_VARIANT_3=0x200C,
                VT_DECIMAL_3=0x200E,
                VT_I1_3=0x2010,
                VT_UI1_3=0x2011,
                VT_UI2_3=0x2012,
                VT_UI4_3=0x2013,
                VT_INT_3=0x2016,
                VT_UINT_3=0x2017
            ),
            "Padding" / Bytes(2),
            # "Value" / If(this.Type=='VT_LPWSTR', UnicodeString)
        )

        ExtraData = "ExtraData" / Struct(
            "BlockSize" / Int32ul,
            "BlockSignature" / Int32ul,
            "ConsoleDataBlock" / If(this.BlockSignature == 0xA0000002, Struct(
                "FileAttributes" / Enum(Int16ul,
                    FOREGROUND_BLUE=0x001,
                    FOREGROUND_GREEN=0x002,
                    FOREGROUND_RED=0x004,
                    FOREGROUND_INTENSITY=0x008,
                    BACKGROUND_BLUE=0x010,
                    BACKGROUND_GREEN=0x020,
                    BACKGROUND_RED=0x040,
                    BACKGROUND_INTENSITY=0x0080
                ),
                "PopupFillAttributes" / Enum(Int16ul,
                    FOREGROUND_BLUE=0x001,
                    FOREGROUND_GREEN=0x002,
                    FOREGROUND_RED=0x004,
                    FOREGROUND_INTENSITY=0x008,
                    BACKGROUND_BLUE=0x010,
                    BACKGROUND_GREEN=0x020,
                    BACKGROUND_RED=0x040,
                    BACKGROUND_INTENSITY=0x0080
                ),
                "ScreenBufferSizeX" / Int16ul,
                "ScreenBufferSizeY" / Int16ul,
                "WindowSizeX" / Int16ul,
                "WindowSizeY" / Int16ul,
                "WindowOriginX" / Int16ul,
                "WindowOriginY" / Int16ul,
                "Unused1" / Bytes(4),
                "Unused2" / Bytes(4),
                "FontSize" / Int32ul,
                "FontFamily" / Enum(Int32ul,
                    FF_DONTCARE=0x0000,
                    FF_ROMAN=0x0010,
                    FF_SWISS=0x0020,
                    FF_MODERN=0x0030,
                    FF_SCRIPT=0x0040,
                    FF_DECORATIVE=0x0050,
                    TMPF_NONE=0x0000,
                    TMPF_FIXED_PITCH=0x0001,
                    TMPF_VECTOR=0x0002,
                    TMPF_TRUETYPE=0x0004,
                    TMPF_DEVICE=0x0004
                ),
                "FontWeight" / Int32ul,
                "FaceName" / Bytes(64),
                "CursorSize" / Int32ul,
                "FullScreen" / Int32ul,
                "QuickEdit" / Int32ul,
                "InsertMode" / Int32ul,
                "AutoPosition" / Int32ul,
                "HistoryBufferSize" / Int32ul,
                "NumberOfHistoryBuffers" / Int32ul,
                "HistoryNoDup" / Int32ul,
                "ColorTable"/ Bytes(64)
            )),
            "ConsoleFEDataBlock" / If(this.BlockSignature == 0xA0000004, Struct(
                "CodePage" / Int32ul
            )),
            "DarwinDataBlock" / If(this.BlockSignature == 0xA0000006, Struct(
                "TargetAnsi" / CString("utf8"),
                "TargetUnicode" / CString("utf16")
            )),
            "EnvironmentVariableDataBlock" / If(this.BlockSignature == 0xA0000001, Struct(
                "TargetAnsi" / CString("utf8"),
                "TargetUnicode" / CString("utf16")
            )),
            "IconEnvironmentDataBlock" / If(this.BlockSignature == 0xA0000007, Struct(
                "TargetAnsi" / CString("utf8"),
                "TargetUnicode" / CString("utf16")
            )),
            "KnownFolderDataBlock" / If(this.BlockSignature == 0xA000000B, Struct(
                "KnownFolderID" / Bytes(16),
                "Offset" / Int32ul,
            )),
            "PropertyStoreDataBlock" / If(this.BlockSignature == 0xA0000009, Struct(
                "PropertyStore" / Struct(
                    # "StoreSize" / Int32ul,
                    "SerializedPropertyStorage" / Struct(
                        "StorageSize" / Int32ul,
                        "Version" / Int32ul,
                        "FormatID" / Bytes(16),
                        "StringName" / IfThenElse(this.FormatID == b'\xd5\xcd\xd5\x05\x2e\x9c\x10\x1b\x93\x97\x08\x00\x2b\x2c\xf9\xae',
                            Struct(
                                "ValueSize" / Int32ul,
                                "NameSize" / Int32ul,
                                "Reserved" / Bytes(1),
                                "Name" / CString("utf16"),
                                "TypedPropertyValue" / TypedPropertyValue
                            ),
                            Struct(
                                "ValueSize" / Int32ul,
                                "Id" / Int32ul,
                                "Reserved" / Bytes(1),
                                "TypedPropertyValue" / TypedPropertyValue
                            )),
                    )
                )
            )),
            "ShimDataBlock" / If(this.BlockSignature == 0xA0000008, Struct(
                "LayerName" / CString("utf16")
            )),
            "SpecialFolderDataBlock" / If(this.BlockSignature == 0xA0000005, Struct(
                "SpecialFolderID" / Int32ul,
                "Offset" / Int32ul,
                "LinkTargetIDList" / LinkTargetIDList,
            )),
            "TrackerDataBlock" / If(this.BlockSignature == 0xA0000003, Struct(
                "Length" / Int32ul,
                "Version" / Int32ul,
                "MachineID" / Bytes(16),
                "Droid" / Bytes(32),
                "DroidBirth" / Bytes(32)
            )),
            "VistaAndAboveIDListDataBlock" / If(this.BlockSignature == 0xA000000C, Struct(
                "ItemIDList" / GreedyRange(Struct(
                    "ItemIDSize" / Int16ul,
                    "Data" / Bytes(this.ItemIDSize - 2),
                )),
                "TerminalID" / Int16ul
            )),
        )

        ShellLinkHeader = "ShellLinkHeader" / Struct(
            "HeaderSize" / Int32ul,
            "LinkCLSID" / Bytes(16),
            "LinkFlags" / BitsSwapped(BitStruct(
                "HasLinkTargetIDList" / Flag,
                "HasLinkInfo" / Flag,
                "HasName" / Flag,
                "HasRelativePath" / Flag,
                "HasWorkingDir" / Flag,
                "HasArguments" / Flag,
                "HasIconLocation" / Flag,
                "IsUnicode" / Flag,
                "ForceNoLinkInfo" / Flag,
                "HasExpString" / Flag,
                "RunInSeparateProcess" / Flag,
                "Unused1" / Flag,
                "HasDarwinID" / Flag,
                "RunAsUser" / Flag,
                "HasExpIcon" / Flag,
                "NoPidlAlias" / Flag,
                "Unused2" / Flag,
                "RunWithShimLayer" / Flag,
                "ForceNoLinkTrack" / Flag,
                "EnableTargetMetadata" / Flag,
                "DisableLinkPathTracking" / Flag,
                "DisableKnownFolderTracking" / Flag,
                "DisableKnownFolderAlias" / Flag,
                "AllowLinkToLink" / Flag,
                "UnaliasOnSave" / Flag,
                "PreferEnvironmentPath" / Flag,
                "KeepLocalIDListForUNCTarget" / Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag
            )),
            "FileAttributes" / BitsSwapped(BitStruct(
                "FILE_ATTRIBUTE_READONLY" / Flag,
                "FILE_ATTRIBUTE_READONLY" / Flag,
                "FILE_ATTRIBUTE_SYSTEM" / Flag,
                "Reserved1" / Flag,
                "FILE_ATTRIBUTE_DIRECTORY" / Flag,
                "FILE_ATTRIBUTE_ARCHIVE" / Flag,
                "Reserved2" / Flag,
                "FILE_ATTRIBUTE_NORMAL" / Flag,
                "FILE_ATTRIBUTE_TEMPORARY" / Flag,
                "FILE_ATTRIBUTE_SPARSE_FILE" / Flag,
                "FILE_ATTRIBUTE_REPARSE_POINT" / Flag,
                "FILE_ATTRIBUTE_COMPRESSED" / Flag,
                "FILE_ATTRIBUTE_OFFLINE" / Flag,
                "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED" / Flag,
                "FILE_ATTRIBUTE_ENCRYPTED" / Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag
            )),
            "CreationTime" / Bytes(8),
            "AccessTime" / Bytes(8),
            "WriteTime" / Bytes(8),
            "FileSize" / Int32ul,
            "IconIndex" / Int32sl,
            "ShowCommand" / Enum(Int32ul,
                                SW_HIDE=0x00000000,
                                SW_NORMAL=0x00000001,
                                SW_SHOWMINIMIZED=0x00000002,
                                SW_SHOWMAXIMIZED=0x00000003,
                                SW_SHOWNOACTIVATE=0x00000004,
                                SW_SHOW=0x00000005,
                                SW_MINIMIZE=0x00000006,
                                SW_SHOWMINNOACTIVE=0x00000007,
                                SW_SHOWNA=0x00000008,
                                SW_RESTORE=0x00000009,
                                SW_SHOWDEFAULT=0x0000000a,
                                ),
            "HotKey" / Struct(
                "LowByte" / Int8ul,
                "HighByte" / Int8ul
            ),
            "Reserved1" / Bytes(2),
            "Reserved2" / Bytes(4),
            "Reserved3" / Bytes(4)
        )

        CommonNetworkRelativeLink = "CommonNetworkRelativeLink" / Struct(
            "CommonNetworkRelativeLinkSize" / Int32ul,
            "CommonNetworkRelativeLinkFlags" / BitsSwapped(BitStruct(
                "ValidDevice" / Flag,
                "ValideNetType" / Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag
            )),
            "NetNameOffset" / Int32ul,
            "DeviceNameOffset" / Int32ul,
            "NetworkProviderType" / If(this.CommonNetworkRelativeLinkFlags.ValideNetType, Enum(Int32ul,
                WNNC_NET_AVID=0x001A0000,
                WNNC_NET_DOCUSPACE=0x001B0000,
                WNNC_NET_MANGOSOFT=0x001C0000,
                WNNC_NET_SERNET=0x001D0000,
                WNNC_NET_RIVERFRONT1=0X001E0000,
                WNNC_NET_RIVERFRONT2=0x001F0000,
                WNNC_NET_DECORB=0x0020000,
                WNNC_NET_PROTSTOR=0x00210000,
                WNNC_NET_FJ_REDIR=0x00220000,
                WNNC_NET_DISTINCT=0x00230000,
                WNNC_NET_TWINS=0x00240000,
                WNNC_NET_RDR2SAMPLE=0x00250000,
                WNNC_NET_CSC=0x00260000,
                WNNC_NET_3IN1=0x00270000,
                WNNC_NET_EXTENDNET=0x00290000,
                WNNC_NET_STAC=0x002A0000,
                WNNC_NET_FOXBAT=0x002B0000,
                WNNC_NET_YAHOO=0x002C0000,
                WNNC_NET_EXIFS=0x002D0000,
                WNNC_NET_DAV=0x002E0000,
                WNNC_NET_KNOWARE=0x002F0000,
                WNNC_NET_OBJECT_DIRE=0x00300000,
                WNNC_NET_MASFAX=0x00310000,
                WNNC_NET_HOB_NFS=0x00320000,
                WNNC_NET_SHIVA=0x00330000,
                WNNC_NET_IBMAL=0x00340000,
                WNNC_NET_LOCK=0x00350000,
                WNNC_NET_TERMSRV=0x00360000,
                WNNC_NET_SRT=0x00370000,
                WNNC_NET_QUINCY=0x00380000,
                WNNC_NET_OPENAFS=0x00390000,
                WNNC_NET_AVID1=0X003A0000,
                WNNC_NET_DFS=0x003B0000,
                WNNC_NET_KWNP=0x003C0000,
                WNNC_NET_ZENWORKS=0x003D0000,
                WNNC_NET_DRIVEONWEB=0x003E0000,
                WNNC_NET_VMWARE=0x003F0000,
                WNNC_NET_RSFX=0x00400000,
                WNNC_NET_MFILES=0x00410000,
                WNNC_NET_MS_NFS=0x00420000,
                WNNC_NET_GOOGLE=0x00430000
            )),
            If(this.NetNameOffset > 0x00000014, "NetNameOffsetUnicode" / Int32ul),
            If(this.NetNameOffset > 0x00000014, "DeviceNameOffsetUnicode" / Int32ul),
            "NetName" / CString("utf8"),
            If(this.NetNameOffset > 0x00000014, "DeviceName" / CString("utf8")),
            If(this.NetNameOffset > 0x00000014, "NetNameUnicode" / CString("utf16")),
        )

        LinkInfo = "LinkInfo" / Struct(
            "LinkInfoSize" / Int32ul,
            "LinkInfoHeaderSize" / Int32ul,
            "LinkInfoFlags" / BitsSwapped(BitStruct(
                "VolumeIDAndLocalBasePath" / Flag,
                "CommonNetworkRelativeLinkAndPathSuffix" / Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag,
                Flag
            )),
            "VolumeIDOffset" / Int32ul,
            "LocalBasePathOffset" / Int32ul,
            "CommonNetworkRelativeLinkOffset" / Int32ul,
            "CommonPathSuffixOffset" / Int32ul,
            "LocalBasePathOffsetUnicode" / If(this.LinkInfoHeaderSize >= 0x24, Int32ul),
            "CommonPathSuffixOffsetUnicode" / If(this.LinkInfoHeaderSize >= 0x24, Int32ul),
            "VolumeID" / Struct(
                "VolumeIDSize" / Int32ul,
                "DriveType" / Enum(Int32ul,
                                DRIVE_UNKNOWN=0x00000000,
                                DRIVE_NO_ROOT_DIR=0x00000001,
                                DRIVE_REMOVABLE=0x00000002,
                                DRIVE_FIXED=0x00000003,
                                DRIVE_REMOTE=0x00000004,
                                DRIVE_CDROM=0x00000005,
                                DRIVE_RAMDISK=0x00000006
                                ),
                "DriveSerialNumber" / Int32ul,
                "VolumeLabelOffset" / Int32ul,
                "VolumeLabelOffsetUnicode" / If(this.VolumeLabelOffset == 0x14, Int32ul),
                "Data" / CString("utf8"),
            ),
            "LocalBasePath" / If(this.LinkInfoFlags.VolumeIDAndLocalBasePath, CString("utf8")),
            "CommonNetworkRelativeLink" / If(this.CommonNetworkRelativeLinkOffset, CommonNetworkRelativeLink),
            "CommonPathSuffix" / CString("utf8"),
            "LocalBasePathUnicode" / If(this.LinkInfoHeaderSize == 0x24, If(this.LocalBasePathOffsetUnicode, CString("utf16"))),
            "CommonPathSuffixUnicode" / If(this.LinkInfoHeaderSize == 0x24, If(this.CommonPathSuffixOffsetUnicode, CString("utf16"))),
        )

        header = ShellLinkHeader.parse(lnk_data)
        offset = header.HeaderSize

        try:
            if header.LinkFlags.HasLinkTargetIDList:
                linktargetidlist = LinkTargetIDList.parse(data[offset:])
                offset += linktargetidlist.IDListSize + 2
        except:
            self.flags.append("Unable to parse LinkTargetIDList")

        try:
            if header.LinkFlags.HasLinkInfo:
                linkinfo = LinkInfo.parse(data[offset:])
                if linkinfo.VolumeID.DriveType:
                    self.event['DriveType'] = linkinfo.VolumeID.DriveType
                if linkinfo.VolumeID.DriveSerialNumber:
                    self.event["DriveSerialNumber"] = '{0:x}'.format(linkinfo.VolumeID.DriveSerialNumber)
                if linkinfo.VolumeID.Data:
                    self.event["VolumeLabel"] = linkinfo.VolumeID.Data
                if linkinfo.LocalBasePath:
                    self.event["LocalBasePath"] = linkinfo.LocalBasePath
                if linkinfo.CommonNetworkRelativeLink:
                    commonnetworkrelativelink = CommonNetworkRelativeLink.parse(data[offset + linkinfo.CommonNetworkRelativeLinkOffset:])
                    self.event["NetName"] = commonnetworkrelativelink.NetName
                offset += linkinfo.LinkInfoSize
        except:
            self.flags.append("Unable to parse LinkInfo")

        StringData = "StringData" / Struct(
        "CountCharacters" / Int16ul,
        "String" / IfThenElse(header.LinkFlags.IsUnicode, StringEncoded(Bytes(this.CountCharacters * 2), "utf16"), StringEncoded(Bytes(this.CountCharacters), "utf8"))
        )
        
        try:
            if header.LinkFlags.HasName:
                NAME_STRING = StringData.parse(data[offset:])
                self.event["NAME_STRING"] = NAME_STRING.String
                if header.LinkFlags.IsUnicode:
                    offset += (len(NAME_STRING.String) * 2 + 2)
                else:
                    offset += (len(NAME_STRING.String) + 2)
        except:
            self.flags.append("Unable to parse NAME_STRING")
        
        try:
            if header.LinkFlags.HasRelativePath:
                RELATIVE_PATH = StringData.parse(data[offset:])
                self.event["RELATIVE_PATH"] = RELATIVE_PATH.String
                if header.LinkFlags.IsUnicode:
                    offset += (len(RELATIVE_PATH.String) * 2 + 2)
                else:
                    offset += (len(RELATIVE_PATH.String) + 2)
        except:
            self.flags.append("Unable to parse RELATIVE_PATH")

        try:    
            if header.LinkFlags.HasWorkingDir:
                WORKING_DIR = StringData.parse(data[offset:])
                self.event["WORKING_DIR"] = WORKING_DIR.String
                if header.LinkFlags.IsUnicode:
                    offset += (len(WORKING_DIR.String) * 2 + 2)
                else:
                    offset += (len(WORKING_DIR.String) + 2)
        except:
            self.flags.append("Unable to parse WORKING_DIR")
        
        try:
            if header.LinkFlags.HasArguments:
                COMMAND_LINE_ARGUMENTS = StringData.parse(data[offset:])
                self.event["COMMAND_LINE_ARGUMENTS"] = COMMAND_LINE_ARGUMENTS.String
                if header.LinkFlags.IsUnicode:
                    offset += (len(COMMAND_LINE_ARGUMENTS.String) * 2 + 2)
                else:
                    offset += (len(COMMAND_LINE_ARGUMENTS.String) + 2)
        except:
            self.flags.append("Unable to parse COMMAND_LINE_ARGUMENTS")

        try:
            if header.LinkFlags.HasIconLocation:
                ICON_LOCATION = StringData.parse(data[offset:])
                self.event["ICON_LOCATION"] = ICON_LOCATION.String
                if header.LinkFlags.IsUnicode:
                    offset += (len(ICON_LOCATION.String) * 2 + 2)
                else:
                    offset += (len(ICON_LOCATION.String) + 2)
        except:
            self.flags.append("Unable to parse ICON_LOCATION")
        
        try:
            blocksize = True
            while blocksize:
                try:
                    extradata = ExtraData.parse(data[offset:])
                    blocksize = extradata.BlockSize
                except:
                    break
                
                try:
                    if extradata.IconEnvironmentDataBlock:
                        self.event["IconTarget"] = extradata.IconEnvironmentDataBlock.TargetAnsi
                except:
                    self.flags.append("Unable to parse IconEnvironmentDataBlock")

                if extradata.TrackerDataBlock:
                    self.event["MachineID"] = extradata.TrackerDataBlock.MachineID.strip(b'\x00')
                    self.event["MAC"] = str(uuid.UUID(bytes_le=extradata.TrackerDataBlock.Droid[16:])).split('-')[-1]

                offset += extradata.BlockSize
        except:
            self.flags.append("Unable to parse ExtraDataBlock")
