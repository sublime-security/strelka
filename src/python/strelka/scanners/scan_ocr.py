import os
import subprocess
import tempfile

import fitz
from strelka import strelka


class ScanOcr(strelka.Scanner):
    """Collects metadata and extracts optical text from image files.

    Options:
        extract_text: Boolean that determines if optical text should be
            extracted as a child file.
            Defaults to False.
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """

    def scan(self, data, file, options, expire_at):
        extract_text = options.get('extract_text', False)
        tmp_directory = options.get('tmp_directory', '/tmp/')
        pdf_to_png = options.get('pdf_to_png', False)

        if pdf_to_png and 'application/pdf' in file.flavors.get('mime', []):
            # TODO: Use fitz builtin OCR support which also wraps tesseract
            doc = fitz.open(stream=data, filetype='pdf')
            data = doc.get_page_pixmap(0, dpi=150).tobytes('png')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_tess:
                tess_return = subprocess.call(
                    ['tesseract', tmp_data.name, tmp_tess.name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                tess_txt_name = f'{tmp_tess.name}.txt'
                if tess_return == 0:
                    with open(tess_txt_name, 'rb') as tess_txt:
                        ocr_file = tess_txt.read().rstrip()

                        # Convert line endings and strip trailing whitespace per line
                        ocr_file = b'\n'.join([line.rstrip() for line in ocr_file.splitlines()])

                        if ocr_file:
                            self.event['raw'] = ocr_file

                            if extract_text:
                                extract_file = strelka.File(
                                    name='text',
                                    source=self.name,
                                )

                                for c in strelka.chunk_string(ocr_file):
                                    self.upload_to_coordinator(
                                        extract_file.pointer,
                                        c,
                                        expire_at,
                                    )

                                self.files.append(extract_file)

                else:
                    self.flags.append(f'return_code_{tess_return}')
                os.remove(tess_txt_name)
