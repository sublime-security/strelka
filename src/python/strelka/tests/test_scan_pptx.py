from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_pptx import ScanPptx as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_pptx(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "author": "",
        "category": "",
        "comments": "generated using python-pptx",
        "content_status": "",
        "created": mock.ANY,
        "identifier": "",
        "keywords": "",
        "language": "",
        "last_modified_by": "Test Author",
        "modified": mock.ANY,
        "revision": 1,
        "subject": "",
        "title": "",
        "version": "",
        "slide_count": 4,
        "word_count": mock.ANY,
        "image_count": 1,
        "notes": [
            "Speaker notes for slide 1: Introduction to contract update.",
            "Speaker notes for slide 2: Summary of key changes.",
            "Speaker notes for slide 3: Required steps for completion.",
            "Speaker notes for slide 4: Contact information and support.",
        ],
        "urls": [
            "https://test.tracking-domain.example.com/click/https%3A%2F%2Fphishing.example.com%2Flogin/tracking-id-12345#6a6f686e2e646f65406578616d706c652e636f6d"
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_pptx_extracts_text(mocker):
    """
    Pass: Text extraction produces expected content.
    Failure: Text not extracted or content doesn't match.
    """

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
        options={"extract_text": True},
    )

    # Verify slide count and word count are populated
    assert scanner_event.get("slide_count") == 4
    assert scanner_event.get("word_count") == 307
    assert scanner_event.get("image_count") == 1


def test_scan_pptx_extracts_urls(mocker):
    """
    Pass: Urls are extracted from the presentation.
    Failure: Urls not found or malformed.
    """

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
    )

    # Verify urls are captured (sanitized test URLs)
    urls = scanner_event.get("urls", [])
    assert len(urls) == 1
    assert "tracking-domain.example.com" in urls[0]
    assert "phishing.example.com" in urls[0]


def test_scan_pptx_extracts_notes(mocker):
    """
    Pass: Speaker notes are extracted from slides.
    Failure: Notes not found or content doesn't match.
    """

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test.pptx",
    )

    # Verify notes are captured
    notes = scanner_event.get("notes", [])
    assert len(notes) == 4
    assert "Speaker notes for slide 1" in notes[0]
    assert "Speaker notes for slide 4" in notes[3]
