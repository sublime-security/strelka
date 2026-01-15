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
        self.always_keep_regex = re.compile(r'0x|qr|/js', re.IGNORECASE)

    def _has_class_run(self, s: str, n: int) -> bool:
        prev = None
        run = 0

        for c in s:
            if c.islower():
                cls = "l"
            elif c.isupper():
                cls = "u"
            elif c.isdigit():
                cls = "d"
            else:
                cls = "o"

            if cls == prev:
                run += 1
            else:
                prev = cls
                run = 1

            # Any run of three consecutive lowercase, uppercase, or digits is sufficient
            if cls != "o" and run >= n:
                return True

        return False

    def _delimiters_in_order(self, s: str) -> bool:
        seen = set()

        for c in s:
            if c in "([{":
                seen.add(c)
            elif c == ")" and "(" not in seen:
                return False
            elif c == "]" and "[" not in seen:
                return False
            elif c == "}" and "{" not in seen:
                return False

        return True

    def _keep_string(self, s: str) -> bool:
        if len(s) >= 7:
            return True

        if self.always_keep_regex.search(s):
            return True

        if not self._has_class_run(s, n=3):
            return False

        return self._delimiters_in_order(s)

    def _has_class_run(self, s: str, n: int) -> bool:
        prev = None
        run = 0

        for c in s:
            if c.isalpha():
                cls = "a"
            elif c.isdigit():
                cls = "d"
            else:
                cls = "o"

            if cls == prev:
                run += 1
            else:
                prev = cls
                run = 1

            # Any run of three consecutive lowercase, uppercase, or digits is sufficient
            if cls != "o" and run >= n:
                return True

        return False

    def _delimiters_in_order(self, s: str) -> bool:
        seen = set()

        for c in s:
            if c in "([{":
                seen.add(c)
            elif c == ")" and "(" not in seen:
                return False
            elif c == "]" and "[" not in seen:
                return False
            elif c == "}" and "{" not in seen:
                return False

        return True

    def _keep_string(self, s: str) -> bool:
        if len(s) >= 7:
            return True

        if not self._has_class_run(s, n=3):
            return False

        return self._delimiters_in_order(s)

    def scan(self, data, file, options, expire_at):
        limit = options.get('limit', 0)
        enable_raw = options.get('enable_raw', False)
        successful_decode = False

        if enable_raw:
            try: 
                raw = data.decode("utf-8")
                if isinstance(raw, str):
                    successful_decode = True
                    self.event['raw'] = raw
            except UnicodeDecodeError:
                self.flags.append(f"unicode_decode_error_{file.uid}")
            except ValueError:
                self.flags.append(f"value_error_{file.uid}")

        # All strings are ASCII decodable per the regex, safe to decode.
        # Use a temporary dict to deduplicate while preserving order.
        strings = list({s.decode("ascii"): 0 for s in self.strings_regex.findall(data)})

        # If the input text isn't fully UTF-8 text, assume that there's garbage ASCII sequences to filter out.
        if not successful_decode:
            strings = [s for s in strings if self._keep_string(s)]

        if limit:
            strings = strings[:limit]

        self.event['strings'] = strings
