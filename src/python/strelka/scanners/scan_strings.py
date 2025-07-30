import re

from strelka import strelka


class ScanStrings(strelka.Scanner):
    """Collects strings from files.

    Collects strings from files (similar to the output of the Unix 'strings'
    utility).

    Options:
        limit: Maximum number of strings to collect, starting from the
            beginning of the file. If this value is 0, then all strings are
            collected.
            Defaults to 0 (unlimited).
    """
    def init(self):
        self.strings_regex = re.compile(br'[^\x00-\x1F\x7F-\xFF]{4,}')

    def scan(self, data, file, options, expire_at):
        limit = options.get('limit', 0)
        enable_raw = options.get('enable_raw', False)
        if enable_raw:
            try: 
                raw = data.decode("utf-8")
                if isinstance(raw, str):
                    self.event['raw'] = raw
            except UnicodeDecodeError:
                self.flags.append(f"unicode_decode_error_{file.uid}")
            except ValueError:
                self.flags.append(f"value_error_{file.uid}")

        strings = self.strings_regex.findall(data)
        if limit:
            strings = strings[:limit]
        self.event['strings'] = strings
