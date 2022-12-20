import entropy

from strelka import strelka


class ScanEntropy(strelka.Scanner):
    """Calculates entropy of files."""
    scan(self, data, file, options, expire_at):
        self.event['entropy'] = entropy.shannon_entropy(data)
