"""
Standalone tests for ScanUrl HTML entity decoding.
Run with: python -m pytest src/python/strelka/tests/test_scan_url_standalone.py -v
"""
import html
import importlib.util
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

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
        assert b'lang=en' in matched
