import glob
import os

import yara

from strelka import strelka


class ScanYara(strelka.Scanner):
    """Scans files with YARA.

    Attributes:
        compiled_yara: Compiled YARA file derived from YARA rule file(s)
            in location.

    Options:
        location: Location of the YARA rules file or directory.
            Defaults to '/etc/yara/'.
        meta: List of YARA rule meta identifiers
            (e.g. 'Author') that should be logged.
            Defaults to empty list.
    """
    def init(self):
        self.compiled_yara = None

    def scan(self, data, file, options, expire_at, custom_fields={}):
        location = options.get('location', '/etc/yara/')
        meta = options.get('meta', [])
        meta = ['author', 'description']

        compiled_custom_yara = None
        if custom_fields.get('source'):
            compiled_custom_yara = yara.compile(source=custom_fields['source'])

        try:
            if self.compiled_yara is None:
                if os.path.isdir(location):
                    globbed_yara_paths = glob.iglob(f'{location}/**/*.yar*', recursive=True)
                    yara_filepaths = {f'namespace_{i}':entry for (i, entry) in enumerate(globbed_yara_paths)}
                    self.compiled_yara = yara.compile(filepaths=yara_filepaths)
                else:
                    self.compiled_yara = yara.compile(filepath=location)

        except (yara.Error, yara.SyntaxError):
            self.flags.append('compiling_error')

        self.event['matches'] = []
        self.event['tags'] = []
        self.event['meta'] = []

        try:
            if self.compiled_yara is not None:
                yara_matches = self.compiled_yara.match(data=data)
                custom_yara_matches = compiled_custom_yara.match(data=data)
                yara_matches.extend(custom_yara_matches)
                for match in yara_matches:
                    self.event['matches'].append(match.rule)
                    #self.event['matches'].append({
                    #    'rule': match.rule,
                    #})
                    if match.tags:
                        for tag in match.tags:
                            if not tag in self.event['tags']:
                                self.event['tags'].append(tag)

                    for k, v in match.meta.items():
                        if meta and k not in meta:
                            continue

                        self.event['meta'].append({
                            'rule': match.rule,
                            'identifier': k,
                            'value': v,
                        })

        except (yara.Error, yara.TimeoutError):
            self.flags.append('scanning_error')
