"""
Standalone tests for ScanUrl HTML entity decoding.
Run with: python -m pytest src/python/strelka/tests/test_scan_url_standalone.py -v
"""
import html
import importlib.util
import re
import ast
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Stub out the strelka framework so scan_url.py can be loaded without its deps.
for _mod in ('strelka', 'strelka.strelka'):
    sys.modules.setdefault(_mod, MagicMock())

_scanner_path = Path(__file__).parent.parent / 'scanners' / 'scan_url.py'
_spec = importlib.util.spec_from_file_location('scan_url', _scanner_path)
_scan_url_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scan_url_mod)

URL_REGEX = re.compile(_scan_url_mod._DEFAULT_URL_PATTERN)
STRIP_CHARS = b'!"#$%&\'()*+,-./@:;<=>[\\]^_`{|}~'


def extract_urls(data: bytes) -> list[bytes]:
    """Replicate ScanUrl.scan() URL extraction with html.unescape() applied."""
    decoded = html.unescape(data.decode('utf-8', errors='replace')).encode('utf-8')
    urls = URL_REGEX.findall(decoded)
    result = []
    for url in urls:
        url = url.strip(STRIP_CHARS)
        if url not in result:
            result.append(url)
    return result


class TestScanUrlHtmlEntities:
    """Tests for HTML entity decoding in URL extraction."""

    def test_amp_entity_in_query_string(self):
        """URLs with &amp; entities (e.g. from DOCX .rels XML) are fully extracted."""
        data = (
            b'Target="https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
            b'?scope=openid&amp;prompt=none&amp;client_id=ceee53a2"'
        )
        urls = extract_urls(data)
        assert len(urls) == 1
        url_str = urls[0].decode('utf-8')
        assert 'scope=openid' in url_str
        assert 'prompt=none' in url_str
        assert 'client_id=ceee53a2' in url_str
        assert '&amp;' not in url_str
        assert '&' in url_str

    def test_plain_url_unaffected(self):
        """Plain URLs without entities are still extracted correctly."""
        data = b'Visit https://example.com/path?foo=bar&baz=qux for more info.'
        urls = extract_urls(data)
        assert any(b'example.com' in u for u in urls)
        matched = next(u for u in urls if b'example.com' in u)
        assert b'foo=bar' in matched
        assert b'baz=qux' in matched

    def test_multiple_amp_entities(self):
        """Multiple &amp; entities across query params are all decoded."""
        data = b'href="https://example.com/sso?a=1&amp;b=2&amp;c=3&amp;d=4"'
        urls = extract_urls(data)
        assert len(urls) == 1
        url_str = urls[0].decode('utf-8')
        assert 'a=1' in url_str
        assert 'b=2' in url_str
        assert 'c=3' in url_str
        assert 'd=4' in url_str
        assert '&amp;' not in url_str

    def test_lt_gt_entities_decoded(self):
        """&lt; and &gt; entities are decoded without breaking URL extraction."""
        data = b'url: https://example.com/search?q=hello&amp;lang=en note &lt;end&gt;'
        urls = extract_urls(data)
        assert any(b'example.com' in u for u in urls)
        matched = next(u for u in urls if b'example.com' in u)
        assert b'q=hello' in matched


_ICS = {'yara': ['ics_file'], 'mime': ['text/calendar']}
_strelka_path = Path(__file__).parent.parent / 'strelka.py'


def _load_real_normalize_whitespace():
    """Returns strelka.strelka.normalize_whitespace without importing strelka.

    strelka.py needs the full framework dependencies, so the function is pulled
    out of the source and compiled on its own. This keeps the tests tied to the
    real implementation instead of a copy.
    """
    tree = ast.parse(_strelka_path.read_text())
    func = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == 'normalize_whitespace')
    namespace = {'re': re}
    exec(compile(ast.Module(body=[func], type_ignores=[]), str(_strelka_path), 'exec'), namespace)
    return namespace['normalize_whitespace']


def _load_scan_url_with_real_base():
    """Loads scan_url.py so that ScanUrl is a real class whose scan() can be called.

    The module-level MagicMock stub makes ScanUrl itself a MagicMock, so a minimal
    Scanner base class stands in for the framework's.
    """
    class Scanner:
        def __init__(self):
            self.event = {}
            self.scanner_timeout = 10
            self.init()

        def init(self):
            pass

    inner = types.SimpleNamespace(Scanner=Scanner, normalize_whitespace=_load_real_normalize_whitespace())
    pkg = types.ModuleType('strelka')
    pkg.strelka = inner
    spec = importlib.util.spec_from_file_location('scan_url_real_base', _scanner_path)
    mod = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'strelka': pkg, 'strelka.strelka': inner}):
        spec.loader.exec_module(mod)
    return mod


_scan_url_real = _load_scan_url_with_real_base()


def _scan(data, flavors=None):
    scanner = _scan_url_real.ScanUrl()
    scanner.scan(data, MagicMock(flavors=flavors or {}), {}, 0)
    return scanner.event['urls']


def _assert_urls(urls, present, absent):
    for url in present:
        assert url in urls
    for url in absent:
        assert url not in urls


class TestUnfoldIcs:
    """Unit tests for _unfold_ics()."""

    @pytest.mark.parametrize('data, expected', [
        pytest.param(b'X:https://exam\r\n ple.com/a', b'X:https://example.com/a', id='crlf-space-fold'),
        pytest.param(b'X:https://exam\n\tple.com/a', b'X:https://example.com/a', id='lf-tab-fold'),
        pytest.param(b'X:https://e\r\n x\r\n a\r\n mple.com', b'X:https://example.com', id='consecutive-folds'),
        pytest.param(b'a\r\n  b', b'a b', id='only-one-whitespace-char-consumed'),
        pytest.param(b'DESCRIPTION:a\\nb', b'DESCRIPTION:a b', id='escaped-newline-lower'),
        pytest.param(b'DESCRIPTION:a\\Nb', b'DESCRIPTION:a b', id='escaped-newline-upper'),
        pytest.param(b'DESCRIPTION:a\\;b\\,c', b'DESCRIPTION:a;b,c', id='escaped-semicolon-and-comma'),
        pytest.param(b'DESCRIPTION:a\\\\b', b'DESCRIPTION:a\\b', id='escaped-backslash'),
        pytest.param(b'DESCRIPTION:a\\\\nb', b'DESCRIPTION:a\\nb', id='escaped-backslash-before-n-is-not-a-newline'),
        pytest.param(b'description;LANGUAGE=en:a\\nb', b'description;LANGUAGE=en:a b', id='text-property-with-params-case-insensitive'),
        pytest.param(b'SUMMARY:a\\,b\r\nLOCATION:c\\;d', b'SUMMARY:a,b\r\nLOCATION:c;d', id='each-text-line-unescaped'),
        pytest.param(b'URL:https://example.com/a\\;b', b'URL:https://example.com/a\\;b', id='url-property-not-unescaped'),
        pytest.param(b'ATTACH:https://example.com/a\\,b', b'ATTACH:https://example.com/a\\,b', id='attach-property-not-unescaped'),
        pytest.param(b'ORGANIZER;CN=a\\;b:mailto:x@example.com', b'ORGANIZER;CN=a\\;b:mailto:x@example.com', id='parameters-not-unescaped'),
        pytest.param(b'X-DESCRIPTION:a\\nb', b'X-DESCRIPTION:a\\nb', id='property-name-must-match-exactly'),
        pytest.param(b'a\\nb', b'a\\nb', id='bare-text-outside-a-property-not-unescaped'),
        pytest.param(b'UID:abc@example.com\r\nX:y', b'\r\nX:y', id='uid-line-dropped'),
        pytest.param(b'uid;X-PARAM=1:abc@example.org\r\nX:y', b'\r\nX:y', id='uid-with-params-case-insensitive'),
        pytest.param(b'PRODID:abc@example.com\r\nX:y', b'\r\nX:y', id='prodid-opaque-id-dropped'),
        pytest.param(b'UID:abc.def+x@example.com\r\nX:y', b'\r\nX:y', id='uid-dot-and-plus-in-local-part-dropped'),
        pytest.param(b'UID:abc@example.com\nX:y', b'\nX:y', id='uid-lf-only-dropped'),
        pytest.param(b'UID:abc@example.com', b'', id='uid-at-end-of-data-dropped'),
        pytest.param(b'PRODID:-//Example Inc//EN\r\nX:y', b'PRODID:-//Example Inc//EN\r\nX:y', id='prodid-non-identifier-kept'),
        pytest.param(b'UID:https://example.com/x\r\nX:y', b'UID:https://example.com/x\r\nX:y', id='uid-with-url-kept'),
        pytest.param(b'UID:abc@example.com/path\r\nX:y', b'UID:abc@example.com/path\r\nX:y', id='uid-with-path-kept'),
        pytest.param(b'UID:abc@example.com extra\r\nX:y', b'UID:abc@example.com extra\r\nX:y', id='uid-with-trailing-text-kept'),
        pytest.param(b'X-UID:abc@example.com\r\nX:y', b'X-UID:abc@example.com\r\nX:y', id='other-property-ending-in-uid-kept'),
        pytest.param(b'UID:abc123def\r\n 456@example.com\r\nX:y', b'\r\nX:y', id='folded-uid-fully-dropped'),
    ])
    def test_unfold_ics(self, data, expected):
        assert _scan_url_mod._unfold_ics(data) == expected

    @pytest.mark.parametrize('flavors, expected', [
        pytest.param({'yara': ['ics_file'], 'mime': ['text/plain']}, True, id='yara-flavor'),
        pytest.param({'mime': ['text/calendar']}, True, id='mime-text-calendar'),
        pytest.param({'mime': ['application/ics']}, True, id='mime-application-ics'),
        pytest.param({'mime': ['text/plain']}, False, id='plain-text'),
        pytest.param({}, False, id='no-flavors'),
    ])
    def test_is_ics_detection(self, flavors, expected):
        assert _scan_url_mod._is_ics(MagicMock(flavors=flavors)) is expected


# (data, flavors, urls that must be found, urls that must not be found)
_SCAN_CASES = [
    pytest.param(
        b'DESCRIPTION:<a href="https://meet.example.co\r\n'
        b' m/meetings/00000000/reschedule">x</a>\\nJoin: https://meet.example.org/abc-\r\n'
        b' defg-hij\\nOr dial\r\n',
        _ICS,
        [b'https://meet.example.com/meetings/00000000/reschedule', b'https://meet.example.org/abc-defg-hij'],
        [b'https://meet.example.co'],
        id='folded-urls-are-rejoined'),
    pytest.param(
        b'Join https://meet.example.co\r\n m/meetings/123/reschedule now\r\n',
        {'mime': ['text/plain']},
        [],
        [b'https://meet.example.com/meetings/123/reschedule'],
        id='non-ics-file-is-not-unfolded'),
    pytest.param(
        b'DESCRIPTION:https://exam\r\n ple.com/a\r\n',
        {'mime': ['application/ics']},
        [b'https://example.com/a'],
        [],
        id='mime-only-flavor-triggers-unfolding'),
    pytest.param(
        b'PRODID:-//Example Inc//Calendar//EN\r\n'
        b'UID:abc123def456@example.com\r\n'
        b'UID;X-PARAM=1:xyz789@example.org\r\n'
        b'ORGANIZER;CN=Test:mailto:organizer@example.com\r\n'
        b'DESCRIPTION:see https://example.net/page\r\n',
        _ICS,
        [b'https://example.net/page', b'mailto:organizer@example.com'],
        [b'abc123def456@example.com', b'xyz789@example.org'],
        id='identifiers-dropped-other-urls-kept'),
    pytest.param(
        b'UID:abc123def\r\n 456@example.com\r\nDESCRIPTION:hi\r\n',
        _ICS,
        [],
        [b'abc123def456@example.com', b'456@example.com'],
        id='folded-uid-does-not-leak'),
    pytest.param(
        b'UID:https://evil.example.net/x\r\nDESCRIPTION:hi\r\n',
        _ICS,
        [b'https://evil.example.net/x'],
        [],
        id='url-in-uid-is-still-extracted'),
    pytest.param(
        b'UID:https://evil.exam\r\n ple.net/x\r\nDESCRIPTION:hi\r\n',
        _ICS,
        [b'https://evil.example.net/x'],
        [],
        id='folded-url-in-uid-is-extracted'),
    pytest.param(
        b'UID:abc.def+x@example.com\r\nUID;X-PARAM=1:abc@example.org\r\nDESCRIPTION:hi\r\n',
        _ICS,
        [],
        [b'example.com', b'1:abc@example.org', b'example.org'],
        id='uid-dot-plus-and-params-do-not-leak'),
]

# Unfolding must run before whitespace normalization: normalize_whitespace
# collapses CRLF + fold whitespace into a space, so a folded URL could not be
# rejoined if it ran first.
_INTERACTION_CASES = [
    pytest.param(
        b'DESCRIPTION:https://example.com/pa\r\n th/to/page\r\n',
        [b'https://example.com/path/to/page'],
        [b'https://example.com/pa'],
        id='fold-not-collapsed-to-space-before-unfold'),
    pytest.param(
        b'DESCRIPTION:https://example.com/a\\nNext line\r\n',
        [b'https://example.com/a'],
        [b'https://example.com/aNext', b'https://example.com/a Next'],
        id='escaped-newline-separates-url-from-next-word'),
    pytest.param(
        b'DESCRIPTION:https://example.com/a\r\n bc\\nhttps://example.org/z\r\n',
        [b'https://example.com/abc', b'https://example.org/z'],
        [],
        id='fold-then-escaped-newline'),
    pytest.param(
        b'DESCRIPTION:https://example.com/a\r\n  https://example.org/b\r\n',
        [b'https://example.com/a', b'https://example.org/b'],
        [],
        id='real-whitespace-after-fold-separates-urls'),
    pytest.param(
        b'DESCRIPTION:https://example.com/a \r\n https://example.org/b\r\n',
        [b'https://example.com/a', b'https://example.org/b'],
        [],
        id='trailing-space-before-fold-separates-urls'),
    pytest.param(
        b'DESCRIPTION:caf\xc3\r\n \xa9 https://example.com/ok\r\n',
        [b'https://example.com/ok'],
        [],
        id='fold-inside-multibyte-utf8-sequence'),
    pytest.param(
        b'DESCRIPTION:https://example.com/a\\;b\r\n',
        [b'https://example.com/a;b'],
        [],
        id='escaped-semicolon-in-url'),
    pytest.param(
        b'DESCRIPTION:https://example.com/?a=1&am\r\n p;b=2\r\n',
        [b'https://example.com/?a=1&b=2'],
        [],
        id='html-entity-split-by-fold-decoded-after-unfolding'),
]


class TestScanUrlScanIcs:
    """End-to-end tests through ScanUrl.scan()."""

    @pytest.mark.parametrize('data, flavors, present, absent', _SCAN_CASES)
    def test_scan(self, data, flavors, present, absent):
        _assert_urls(_scan(data, flavors), present, absent)


class TestScanUrlUnfoldNormalizeInteraction:
    """Unfolding must not be undone or disturbed by whitespace normalization."""

    @pytest.mark.parametrize('data, present, absent', _INTERACTION_CASES)
    def test_scan(self, data, present, absent):
        _assert_urls(_scan(data, _ICS), present, absent)
