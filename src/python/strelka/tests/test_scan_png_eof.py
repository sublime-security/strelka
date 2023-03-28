from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_png_eof import ScanPngEof as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_png_eof(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "trailer_index": 539355,
        "PNG_EOF": b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00PE\x00\x00d\x86\x02\x00\xbcs\x12\xfd\x00\x00\x00\x00\x00\x00\x00\x00\xf0\x00"\x00\x0b\x020\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00@\x01\x00\x00\x00\x00 \x00\x00\x00\x02\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03\x00@\x85\x00\x00@\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\xc0\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00,&\x00\x008\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.text\x00\x00\x00\xcf\x06\x00\x00\x00 \x00\x00\x00\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00`.rsrc\x00\x00\x00\xc0\x05\x00\x00\x00@\x00\x00\x00\x06\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x02\x00\x05\x00\\ \x00\x00\xd0\x05\x00\x00\x01\x00\x00\x00\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.r\x01\x00\x00p(\x0f\x00\x00\n*\x1e\x02(\x10\x00\x00\n*BSJB\x01\x00\x01\x00\x00\x00\x00\x00\x0c\x00\x00\x00v4.0.30319\x00\x00\x00\x00\x05\x00l\x00\x00\x00\xcc\x01\x00\x00#~\x00\x008\x02\x00\x00X\x02\x00\x00#Strings\x00\x00\x00\x00\x90\x04\x00\x00\x1c\x00\x00\x00#US\x00\xac\x04\x00\x00\x10\x00\x00\x00#GUID\x00\x00\x00\xbc\x04\x00\x00\x14\x01\x00\x00#Blob\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x01G\x15\x00\x00\t\x00\x00\x00\x00\xfa\x013\x00\x16\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00\x0e\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x95\x01\x01\x00\x00\x00\x00\x00\x06\x00\n\x01\x1c\x02\x06\x00w\x01\x1c\x02\x06\x00>\x00\xea\x01\x0f\x00<\x02\x00\x00\x06\x00f\x00\xd2\x01\x06\x00\xed\x00\xd2\x01\x06\x00\xce\x00\xd2\x01\x06\x00^\x01\xd2\x01\x06\x00*\x01\xd2\x01\x06\x00C\x01\xd2\x01\x06\x00}\x00\xd2\x01\x06\x00R\x00\xfd\x01\x06\x000\x00\xfd\x01\x06\x00\xb1\x00\xd2\x01\x06\x00\x98\x00\xa4\x01\x06\x00P\x02\xc6\x01\x06\x00\x1e\x00\xc6\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x10\x00\xbe\x01\x13\x00A\x00\x01\x00\x01\x00H \x00\x00\x00\x00\x91\x00\xcd\x01(\x00\x01\x00T \x00\x00\x00\x00\x86\x18\xe4\x01\x06\x00\x02\x00\x00\x00\x01\x00K\x02\t\x00\xe4\x01\x01\x00\x11\x00\xe4\x01\x06\x00\x19\x00\xe4\x01\n\x00)\x00\xe4\x01\x10\x001\x00\xe4\x01\x10\x009\x00\xe4\x01\x10\x00A\x00\xe4\x01\x10\x00I\x00\xe4\x01\x10\x00Q\x00\xe4\x01\x10\x00Y\x00\xe4\x01\x10\x00a\x00\xe4\x01\x15\x00i\x00\xe4\x01\x10\x00q\x00\xe4\x01\x10\x00y\x00\xe4\x01\x10\x00\x89\x00&\x00\x1a\x00\x81\x00\xe4\x01\x06\x00.\x00\x0b\x00.\x00.\x00\x13\x007\x00.\x00\x1b\x00V\x00.\x00#\x00_\x00.\x00+\x00o\x00.\x003\x00o\x00.\x00;\x00u\x00.\x00C\x00_\x00.\x00K\x00|\x00.\x00S\x00o\x00.\x00[\x00o\x00.\x00c\x00\x95\x00.\x00k\x00\xbf\x00.\x00s\x00\xcc\x00\x04\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<Module>\x00mscorlib\x00HelloWorld\x00Console\x00WriteLine\x00GuidAttribute\x00DebuggableAttribute\x00ComVisibleAttribute\x00AssemblyTitleAttribute\x00AssemblyTrademarkAttribute\x00TargetFrameworkAttribute\x00AssemblyFileVersionAttribute\x00AssemblyConfigurationAttribute\x00AssemblyDescriptionAttribute\x00CompilationRelaxationsAttribute\x00AssemblyProductAttribute\x00AssemblyCopyrightAttribute\x00AssemblyCompanyAttribute\x00RuntimeCompatibilityAttribute\x00HelloWorld.exe\x00System.Runtime.Versioning\x00Program\x00System\x00Main\x00System.Reflection\x00.ctor\x00System.Diagnostics\x00System.Runtime.InteropServices\x00System.Runtime.CompilerServices\x00DebuggingModes\x00args\x00Object\x00\x00\x00\x17H\x00e\x00l\x00l\x00o\x00 \x00W\x00o\x00r\x00l\x00d\x00\x00\x00\x00\x00v\x0e\xa4Et\\\xa8L\x98\xd0lw\xcc\x08\xd7O\x00\x04 \x01\x01\x08\x03 \x00\x01\x05 \x01\x01\x11\x11\x04 \x01\x01\x0e\x04 \x01\x01\x02\x04\x00\x01\x01\x0e\x08\xb7z\\V\x194\xe0\x89\x05\x00\x01\x01\x1d\x0e\x08\x01\x00\x08\x00\x00\x00\x00\x00\x1e\x01\x00\x01\x00T\x02\x16WrapNonExceptionThrows\x01\x08\x01\x00\x02\x00\x00\x00\x00\x00\x0f\x01\x00\nHelloWorld\x00\x00\x05\x01\x00\x00\x00\x00\x06\x01\x00\x01.\x00\x00\x18\x01\x00\x13Copyright \xc2\xa9 . 2020\x00\x00)\x01\x00$c66634a4-f119-4236-b8d2-a085d40e57c7\x00\x00\x0c\x01\x00\x071.0.0.0\x00\x00G\x01\x00\x1a.NETFramework,Version=v4.0\x01\x00T\x0e\x14FrameworkDisplayName\x10.NET Framework 4\x00\x00\x00\x00\xfe\x84S\xc9\x00\x00\x00\x00\x02\x00\x00\x00k\x00\x00\x00d&\x00\x00d\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00RSDS\xa6c\x07\xd0\x9b\x84\xb9D\xbf\x03\x0b\xff-}\x1eJ\x01\x00\x00\x00C:\\Users\\tmcguff\\source\\repos\\HelloWorld\\HelloWorld\\obj\\x64\\Release\\HelloWorld.pdb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x10\x00\x00\x00 \x00\x00\x80\x18\x00\x00\x00P\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x008\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00h\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\xc0\x03\x00\x00\x90@\x00\x000\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x034\x00\x00\x00V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00\x00\x00\xbd\x04\xef\xfe\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00?\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D\x00\x00\x00\x01\x00V\x00a\x00r\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00\x00\x00$\x00\x04\x00\x00\x00T\x00r\x00a\x00n\x00s\x00l\x00a\x00t\x00i\x00o\x00n\x00\x00\x00\x00\x00\x00\x00\xb0\x04\x90\x02\x00\x00\x01\x00S\x00t\x00r\x00i\x00n\x00g\x00F\x00i\x00l\x00e\x00I\x00n\x00f\x00o\x00\x00\x00l\x02\x00\x00\x01\x000\x000\x000\x000\x000\x004\x00b\x000\x00\x00\x00\x1a\x00\x01\x00\x01\x00C\x00o\x00m\x00m\x00e\x00n\x00t\x00s\x00\x00\x00\x00\x00\x00\x00$\x00\x02\x00\x01\x00C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00\x00\x00.\x00\x00\x00>\x00\x0b\x00\x01\x00F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00\x00\x00H\x00e\x00l\x00l\x00o\x00W\x00o\x00r\x00l\x00d\x00\x00\x00\x00\x000\x00\x08\x00\x01\x00F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00\x00\x001\x00.\x000\x00.\x000\x00.\x000\x00\x00\x00>\x00\x0f\x00\x01\x00I\x00n\x00t\x00e\x00r\x00n\x00a\x00l\x00N\x00a\x00m\x00e\x00\x00\x00H\x00e\x00l\x00l\x00o\x00W\x00o\x00r\x00l\x00d\x00.\x00e\x00x\x00e\x00\x00\x00\x00\x00J\x00\x13\x00\x01\x00L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00 \x00\xa9\x00 \x00.\x00 \x002\x000\x002\x000\x00\x00\x00\x00\x00*\x00\x01\x00\x01\x00L\x00e\x00g\x00a\x00l\x00T\x00r\x00a\x00d\x00e\x00m\x00a\x00r\x00k\x00s\x00\x00\x00\x00\x00\x00\x00\x00\x00F\x00\x0f\x00\x01\x00O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00H\x00e\x00l\x00l\x00o\x00W\x00o\x00r\x00l\x00d\x00.\x00e\x00x\x00e\x00\x00\x00\x00\x006\x00\x0b\x00\x01\x00P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00\x00\x00H\x00e\x00l\x00l\x00o\x00W\x00o\x00r\x00l\x00d\x00\x00\x00\x00\x004\x00\x08\x00\x01\x00P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x001\x00.\x000\x00.\x000\x00.\x000\x00\x00\x008\x00\x08\x00\x01\x00A\x00s\x00s\x00e\x00m\x00b\x00l\x00y\x00 \x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x001\x00.\x000\x00.\x000\x00.\x000\x00\x00\x00\xd0C\x00\x00\xea\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbb\xbf<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n\r\n<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">\r\n  <assemblyIdentity version="1.0.0.0" name="MyApplication.app"/>\r\n  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">\r\n    <security>\r\n      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">\r\n        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>\r\n      </requestedPrivileges>\r\n    </security>\r\n  </trustInfo>\r\n</assembly>\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_pe_overlay.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_png_eof_normal(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["no_trailer"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_png_eof_no_iend(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {"elapsed": mock.ANY, "flags": ["no_iend_chunk"]}

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_broken_iend.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)