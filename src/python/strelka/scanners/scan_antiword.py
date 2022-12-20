import subprocess
import tempfile

from strelka import strelka


class ScanAntiword(strelka.Scanner):
    """Extracts text from MS Word document files.

    Options:
        tmp_directory: Location where tempfile writes temporary files.
            Defaults to '/tmp/'.
    """
    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get('tmp_directory', '/tmp/')

        with tempfile.NamedTemporaryFile(dir=tmp_directory) as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()

            (stdout, stderr) = subprocess.Popen(
                ['antiword', tmp_data.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL
            ).communicate()

            if stdout:
                extract_file = strelka.File(
                    name='text',
                    source=self.name,
                )

                for c in strelka.chunk_string(stdout):
                    self.upload_to_coordinator(
                        extract_file.pointer,
                        c,
                        expire_at,
                    )

                self.files.append(extract_file)
