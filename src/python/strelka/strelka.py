import json
import logging
import traceback
import uuid
import glob
import importlib
import math
import os
import re
import string
import signal
import time
import magic
import yara

from boltons import iterutils
import inflection
from tldextract import TLDExtract
import ipaddress
import validators


class RequestTimeout(Exception):
    """Raised when request times out."""
    pass


class DistributionTimeout(Exception):
    """Raised when file distribution times out."""
    pass


class ScannerTimeout(Exception):
    """Raised when scanner times out."""
    pass


class File(object):
    """Defines a file that will be scanned.

    This object contains metadata that describes files input into the
    system. The object should only contain data is that is not stored
    elsewhere (e.g. file bytes stored in Redis). In future releases this
    object may be removed in favor of a pure-Redis design.

    Attributes:
        flavors: Dictionary of flavors assigned to the file during distribution.
        uid: String that contains a universally unique identifier (UUIDv4)
            used to uniquely identify the file.
        depth: Integer that represents how deep the file was embedded.
        parent: UUIDv4 of the file that produced this file.
        pointer: String that contains the location of the file bytes in Redis.
        name: String that contains the name of the file.
        source: String that describes which scanner the file originated from.
    """
    def __init__(self, pointer='',
                 parent='', depth=0,
                 name='', source=''):
        """Inits file object."""
        self.flavors = {}
        self.uid = str(uuid.uuid4())
        self.depth = depth
        self.name = name
        self.parent = parent
        self.pointer = pointer or self.uid
        self.source = source

    def add_flavors(self, flavors):
        """Adds flavors to the file.

        In cases where flavors and self.flavors share duplicate keys, flavors
        will overwrite the duplicate value.
        """
        self.flavors = {**self.flavors, **flavors}


class Backend(object):
    def __init__(self, backend_cfg, coordinator):
        self.scanner_cache = {}
        self.backend_cfg = backend_cfg
        self.coordinator = coordinator
        self.limits = backend_cfg.get('limits')
        self.scanners = backend_cfg.get('scanners')

        self.compiled_magic = magic.Magic(
            magic_file=backend_cfg.get('tasting').get('mime_db'),
            mime=True,
        )

        yara_rules = backend_cfg.get('tasting').get('yara_rules')
        if os.path.isdir(yara_rules):
            yara_filepaths = {}
            globbed_yara = glob.iglob(
                f'{yara_rules}/**/*.yar*',
                recursive=True,
            )
            for (i, entry) in enumerate(globbed_yara):
                yara_filepaths[f'namespace{i}'] = entry
            self.compiled_yara = yara.compile(filepaths=yara_filepaths)
        else:
            self.compiled_yara = yara.compile(filepath=yara_rules)

    def timeout_handler(self, ex):
        """Signal timeout handler"""

        def fn(signum, frame):
            raise ex

        return fn

    def work(self):
        logging.info('starting up')

        count = 0
        work_start = time.time()
        work_expire = work_start + self.limits.get('time_to_live')

        while 1:
            if self.limits.get('max_files') != 0:
                if count >= self.limits.get('max_files'):
                    break
            if self.limits.get('time_to_live') != 0:
                if time.time() >= work_expire:
                    break

            task = self.coordinator.zpopmin('tasks', count=1)
            if len(task) == 0:
                time.sleep(0.25)
                continue

            (root_id, expire_at) = task[0]
            root_id = root_id.decode()
            file = File(pointer=root_id)
            expire_at = math.ceil(expire_at)
            timeout = math.ceil(expire_at - time.time())
            if timeout <= 0:
                continue

            try:
                self.signal = signal.signal(
                        signal.SIGALRM,
                        self.timeout_handler(RequestTimeout)
                    )
                signal.alarm(timeout)
                self.distribute(root_id, file, expire_at)
                p = self.coordinator.pipeline(transaction=False)
                p.rpush(f'event:{root_id}', 'FIN')
                p.expireat(f'event:{root_id}', expire_at)
                p.execute()
                signal.alarm(0)
            except RequestTimeout:
                logging.debug(f'request {root_id} timed out')
            except Exception:
                signal.alarm(0)
                logging.exception('unknown exception (see traceback below)')

            count += 1

        logging.info(f'shutdown after scanning {count} file(s) and'
                     f' {time.time() - work_start} second(s)')

    def taste_mime(self, data):
        """Tastes file data with libmagic."""
        return [self.compiled_magic.from_buffer(data)]

    def taste_yara(self, data):
        """Tastes file data with YARA."""
        encoded_whitespace = string.whitespace.encode()
        stripped_data = data.lstrip(encoded_whitespace)
        yara_matches = self.compiled_yara.match(data=stripped_data)
        return [match.rule for match in yara_matches]

    def distribute(self, root_id, file, expire_at):
        """Distributes a file through scanners."""
        try:
            files = []

            try:
                self.signal = signal.signal(
                        signal.SIGALRM,
                        self.timeout_handler(DistributionTimeout)
                    )
                signal.alarm(self.limits.get('distribution'))
                if file.depth > self.limits.get('max_depth'):
                    logging.info(f'request {root_id} exceeded maximum depth')
                    return

                data = b''
                while 1:
                    pop = self.coordinator.lpop(f'data:{file.pointer}')
                    if pop is None:
                        break
                    data += pop

                file.add_flavors({'mime': self.taste_mime(data)})
                file.add_flavors({'yara': self.taste_yara(data)})
                flavors = (
                    file.flavors.get('external', [])
                    + file.flavors.get('mime', [])
                    + file.flavors.get('yara', [])
                )

                scanner_list = []
                for name in self.scanners:
                    mappings = self.scanners.get(name, {})
                    assigned = self.assign_scanner(
                        name,
                        mappings,
                        flavors,
                        file,
                    )
                    if assigned is not None:
                        scanner_list.append(assigned)
                scanner_list.sort(
                    key=lambda k: k.get('priority', 5),
                    reverse=True,
                )

                p = self.coordinator.pipeline(transaction=False)
                tree_dict = {
                    'node': file.uid,
                    'parent': file.parent,
                    'root': root_id,
                }

                if file.depth == 0:
                    tree_dict['node'] = root_id
                if file.depth == 1:
                    tree_dict['parent'] = root_id

                file_dict = {
                    'depth': file.depth,
                    'name': file.name,
                    'flavors': file.flavors,
                    'scanners': [s.get('name') for s in scanner_list],
                    'size': len(data),
                    'source': file.source,
                    'tree': tree_dict,
                }
                scan = {}

                for scanner in scanner_list:
                    try:
                        name = scanner['name']
                        und_name = inflection.underscore(name)
                        scanner_import = f'strelka.scanners.{und_name}'
                        module = importlib.import_module(scanner_import)
                        if und_name not in self.scanner_cache:
                            attr = getattr(module, name)(self.backend_cfg, self.coordinator)
                            self.scanner_cache[und_name] = attr
                        options = scanner.get('options', {})
                        plugin = self.scanner_cache[und_name]
                        (f, s) = plugin.scan_wrapper(
                            data,
                            file,
                            options,
                            expire_at,
                        )
                        files.extend(f)

                        scan = {
                            **scan,
                            **s,
                        }

                    except ModuleNotFoundError:
                        logging.exception(f'scanner {name} not found')

                event = {
                    **{'file': file_dict},
                    **{'scan': scan},
                }

                p.rpush(f'event:{root_id}', format_event(event))
                p.expireat(f'event:{root_id}', expire_at)
                p.execute()
                signal.alarm(0)

            except DistributionTimeout:
                logging.exception(f'node {file.uid} timed out')

            for f in files:
                f.parent = file.uid
                f.depth = file.depth + 1
                self.distribute(root_id, f, expire_at)

        except RequestTimeout:
            signal.alarm(0)
            raise

    def assign_scanner(self, scanner, mappings, flavors, file):
        """Assigns scanners based on mappings and file data.

        Performs the task of assigning scanners based on the scan configuration
        mappings and file flavors, filename, and source. Assignment supports
        positive and negative matching: scanners are assigned if any positive
        categories are matched and no negative categories are matched. Flavors are
        literal matches, filename and source matches uses regular expressions.

        Args:
            scanner: Name of the scanner to be assigned.
            mappings: List of dictionaries that contain values used to assign
                the scanner.
            flavors: List of file flavors to use during scanner assignment.
            filename: Filename to use during scanner assignment.
            source: File source to use during scanner assignment.
        Returns:
            Dictionary containing the assigned scanner or None.
        """
        for mapping in mappings:
            negatives = mapping.get('negative', {})
            positives = mapping.get('positive', {})
            neg_flavors = negatives.get('flavors', [])
            neg_filename = negatives.get('filename', None)
            neg_source = negatives.get('source', None)
            pos_flavors = positives.get('flavors', [])
            pos_filename = positives.get('filename', None)
            pos_source = positives.get('source', None)
            assigned = {'name': scanner,
                        'priority': mapping.get('priority', 5),
                        'options': mapping.get('options', {})}

            for neg_flavor in neg_flavors:
                if neg_flavor in flavors:
                    return None
            if neg_filename is not None:
                if re.search(neg_filename, file.name) is not None:
                    return None
            if neg_source is not None:
                if re.search(neg_source, file.source) is not None:
                    return None
            for pos_flavor in pos_flavors:
                if pos_flavor == '*' or pos_flavor in flavors:
                    return assigned
            if pos_filename is not None:
                if re.search(pos_filename, file.name) is not None:
                    return assigned
            if pos_source is not None:
                if re.search(pos_source, file.source) is not None:
                    return assigned
        return None


class IocOptions(object):
    """
    Defines an ioc options object that can be used to specify the ioc_type for developers as opposed to using a
    string.
    """

    domain = 'domain'
    url = 'url'
    md5 = 'md5'
    sha1 = 'sha1'
    sha256 = 'sha256'
    email = 'email'
    ip = 'ip'


class Scanner(object):
    """Defines a scanner that scans File objects.

    Each scanner inherits this class and overrides methods (init and scan)
    to perform scanning functions.

    Attributes:
        name: String that contains the scanner class name.
            This is referenced in the scanner metadata.
        key: String that contains the scanner's metadata key.
            This is used to identify the scanner metadata in scan results.
        event: Dictionary containing the result of scan
        backend_cfg: Dictionary that contains the parsed backend configuration.
        scanner_timeout: Amount of time (in seconds) that a scanner can spend
            scanning a file. Can be overridden on a per-scanner basis
            (see scan_wrapper).
        coordinator: Redis client connection to the coordinator.
    """
    def __init__(self, backend_cfg, coordinator):
        """Inits scanner with scanner name and metadata key."""
        self.name = self.__class__.__name__
        self.key = inflection.underscore(self.name.replace('Scan', ''))
        self.scanner_timeout = backend_cfg.get('limits', {}).get('scanner', 10)
        self.signal = None
        self.coordinator = coordinator
        self.event = dict()
        self.files = []
        self.flags = []
        self.iocs = []
        self.type = IocOptions
        self.extract = TLDExtract(suffix_list_urls=None)
        self.init()

    def init(self):
        """Overrideable init.

        This method can be used to setup one-time variables required
        during scanning."""
        pass

    def timeout_handler(self, signum, frame):
        """Signal ScannerTimeout"""
        raise ScannerTimeout

    def scan(self,
             data,
             file,
             options,
             expire_at):
        """Overrideable scan method.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        """
        pass

    def scan_wrapper(self,
                     data,
                     file,
                     options,
                     expire_at):
        """Sets up scan attributes and calls scan method.

        Scanning code is wrapped in try/except for error handling.
        The scanner always returns a list of extracted files (which may be
        empty) and metadata regardless of whether the scanner completed
        successfully or hit an exception.

        Args:
            data: Data associated with file that will be scanned.
            file: File associated with data that will be scanned (see File()).
            options: Options to be applied during scan.
            expire_at: Expiration date for any files extracted during scan.
        Returns:
            List of extracted File objects (may be empty).
            Dictionary of scanner metadata.
        Raises:
            DistributionTimeout: interrupts the scan when distribution times out.
            RequestTimeout: interrupts the scan when request times out.
            Exception: Unknown exception occurred.
        """
        start = time.time()
        self.event = dict()
        self.scanner_timeout = options.get('scanner_timeout',
                                           self.scanner_timeout or 10)

        try:
            self.signal = signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(self.scanner_timeout)
            self.scan(data, file, options, expire_at)
            signal.alarm(0)
        except ScannerTimeout:
            self.flags.append('timed_out')
        except (DistributionTimeout, RequestTimeout):
            raise
        except Exception as e:
            signal.alarm(0)
            logging.exception(f'{self.name}: unhandled exception while scanning'
                              f' uid {file.uid if file else "_missing_"} (see traceback below)')
            self.flags.append('uncaught_exception')
            self.event.update({"exception": "\n".join(traceback.format_exception(e, limit=-1))})

        self.event = {
            **{'elapsed': round(time.time() - start, 6)},
            **{'flags': self.flags},
            **self.event
        }
        return (
            self.files,
            {self.key: self.event}
        )

    def upload_to_coordinator(self, pointer, chunk, expire_at):
        """Uploads data to coordinator.

        This method is used during scanning to upload data to coordinator,
        where the data is later pulled from during file distribution.

        Args:
            pointer: String that contains the location of the file bytes
                in Redis.
            chunk: String that contains a chunk of data to be added to
                the coordinator.
            expire_at: Expiration date for data stored in pointer.
        """
        p = self.coordinator.pipeline(transaction=False)
        p.rpush(f'data:{pointer}', chunk)
        p.expireat(f'data:{pointer}', expire_at)
        p.execute()

    def process_ioc(self, ioc, ioc_type, scanner_name, description='', malicious=False):
        if not ioc:
            return
        if ioc_type == 'url':
            if validators.ipv4(self.extract(ioc).domain):
                self.process_ioc(self.extract(ioc).domain, 'ip', scanner_name, description, malicious)
            else:
                self.process_ioc(self.extract(ioc).registered_domain, 'domain', scanner_name, description, malicious)
            if not validators.url(ioc):
                logging.warning(f"{ioc} is not a valid url")
                return
        elif ioc_type == 'ip':
            try:
                ipaddress.ip_address(ioc)
            except ValueError:
                logging.warning(f"{ioc} is not a valid IP")
                return
        elif ioc_type == 'domain':
            if not validators.domain(ioc):
                logging.warning(f"{ioc} is not a valid domain")
                return
        elif ioc_type == 'email':
            if not validators.email(ioc):
                logging.warning(f"{ioc} is not a valid email")
                return

        if malicious:
            self.iocs.append({'ioc': ioc, 'ioc_type': ioc_type, 'scanner': scanner_name, 'description': description,
                              'malicious': True})
        else:
            self.iocs.append({'ioc': ioc, 'ioc_type': ioc_type, 'scanner': scanner_name, 'description': description})

    def add_iocs(self, ioc, ioc_type, description='', malicious=False):
        """Adds ioc to the iocs.
        :param ioc: The IOC or list of IOCs to be added. All iocs must be of the same type. Must be type String or Bytes.
        :param ioc_type: Must be one of md5, sha1, sha256, domain, url, email, ip, either as string or type object (e.g. self.type.domain).
        :param description (Optional): Description of the IOCs.
        :param malicious (Optional): Reasonable determination whether the indicator is or would be used maliciously. Example:
          Malware Command and Control. Should not be used solely for determining maliciousness since testing values may be present.
        """
        try:
            accepted_iocs = ['md5', 'sha1', 'sha256', 'domain', 'url', 'email', 'ip']
            if ioc_type not in accepted_iocs:
                logging.warning(f"{ioc_type} not in accepted range. Acceptable ioc types are: {accepted_iocs}")
                return
            if isinstance(ioc, list):
                for i in ioc:
                    if isinstance(i, bytes):
                        i = i.decode()
                    if not isinstance(i, str):
                        logging.warning(f"Could not process {i} from {self.name}: Type {type(i)} is not type Bytes or String")
                        continue
                    self.process_ioc(i, ioc_type, self.name, description=description, malicious=malicious)
            else:
                if isinstance(ioc, bytes):
                    ioc = ioc.decode()
                if not isinstance(ioc, str):
                    logging.warning(f"Could not process {ioc} from {self.name}: Type {type(ioc)} is not type Bytes or String")
                    return
                self.process_ioc(ioc, ioc_type, self.name, description=description, malicious=malicious)
        except Exception as e:
            logging.error(f"Failed to add {ioc} from {self.name}: {e}")


def chunk_string(s, chunk=1024 * 16):
    """Takes an input string and turns it into smaller byte pieces.

    This method is required for inserting data into coordinator.

    Yields:
        Chunks of the input string.
    """
    if isinstance(s, bytearray):
        s = bytes(s)

    for c in range(0, len(s), chunk):
        yield s[c:c + chunk]


def normalize_whitespace(text):
    """Normalizes whitespace in text.

    Scanners that parse text generally need whitespace normalized, otherwise
    metadata parsed from the text may be unreliable. This function normalizes
    whitespace characters to a single space.

    Args:
        text: Text that needs whitespace normalized.
    Returns:
        Text with whitespace normalized.
    """
    if isinstance(text, bytes):
        text = re.sub(br'\s+', b' ', text)
        text = re.sub(br'(^\s+|\s+$)', b'', text)
    elif isinstance(text, str):
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'(^\s+|\s+$)', '', text)
    return text


def format_event(metadata):
    """Formats file metadata into an event.

    This function must be used on file metadata before the metadata is
    pushed to Redis. The function takes a dictionary containing a
    complete file event and runs the following (sequentially):
        * Replaces all bytes with strings
        * Removes all values that are empty strings, empty lists,
            empty dictionaries, or None
        * Dumps dictionary as JSON

    Args:
        metadata: Dictionary that needs to be formatted into an event.

    Returns:
        JSON-formatted file event.
    """
    def visit(path, key, value):
        if isinstance(value, (bytes, bytearray)):
            value = str(value, encoding='UTF-8', errors='replace')
        return key, value

    remap1 = iterutils.remap(metadata, visit=visit)
    remap2 = iterutils.remap(
        remap1,
        lambda p, k, v: v != '' and v != [] and v != {} and v is not None,
    )
    return json.dumps(remap2)
