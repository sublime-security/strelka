from lxml import etree

from strelka import strelka


class ScanXml(strelka.Scanner):
    """Collects metadata and extracts embedded files from XML files.

    Extracts JavaScript content from script tags and emits them as child files.

    Options:
        extract_tags: List of XML tags that will have their text extracted
            as child files.
            Defaults to empty list.
        metadata_tags: List of XML tags that will have their text logged
            as metadata.
            Defaults to empty list.
    """
    def scan(self, data, file, options, expire_at):
        xml_args = {
            'extract_tags': options.get('extract_tags', []),
            'metadata_tags': options.get('metadata_tags', []),
        }
        self.expire_at = expire_at
        self.event.setdefault('tags', [])
        self.event.setdefault('tag_data', [])
        self.event.setdefault('namespaces', [])
        self.event['total'] = {'tags': 0, 'scripts': 0, 'extracted': 0}

        xml = None
        try:
            xml_buffer = data
            if xml_buffer.startswith(b'<?XML'):
                xml_buffer = b'<?xml' + xml_buffer[5:]
            xml = etree.fromstring(xml_buffer)
            docinfo = xml.getroottree().docinfo
            if docinfo.doctype:
                self.event['doc_type'] = docinfo.doctype
            if docinfo.xml_version:
                self.event['version'] = docinfo.xml_version

        except etree.XMLSyntaxError:
            self.flags.append('syntax_error')

        if xml is not None:
            self._recurse_node(self, xml, xml_args)

    @staticmethod
    def _recurse_node(self, node, xml_args):
        """Recursively parses XML file.

        The XML file is recursively parsed down every node tree.

        Args:
            node: node to be recursively parsed.
            xml_args: options set by the scanner that affect XMl parsing.
        """
        if node is not None:
            if hasattr(node.tag, '__getitem__'):
                if node.tag.startswith('{'):
                    namespace, separator, tag = node.tag[1:].partition('}')
                else:
                    namespace = None
                    tag = node.tag

                self.event['total']['tags'] += 1
                if namespace not in self.event['namespaces']:
                    self.event['namespaces'].append(namespace)
                if tag not in self.event['tags']:
                    self.event['tags'].append(tag)

                text = node.attrib.get('name', node.text)
                if text is not None:
                    if tag in xml_args['metadata_tags']:
                        tag_data = {'tag': tag, 'text': text.strip()}
                        if tag_data not in self.event['tag_data']:
                            self.event['tag_data'].append(tag_data)
                    elif tag in xml_args['extract_tags']:
                        extract_file = strelka.File(
                            name=tag,
                            source=self.name,
                        )

                        for c in strelka.chunk_string(text):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                self.expire_at,
                            )

                        self.files.append(extract_file)
                        self.event['total']['extracted'] += 1

                # Check for script tags and extract JavaScript content
                if tag == 'script':
                    self.event['total']['scripts'] += 1

                    if text and text.strip():
                        extract_file = strelka.File(
                            name=f'script_{self.event["total"]["scripts"]-1}',
                            source=self.name,
                        )
                        script_flavors = [
                            node.attrib.get('type', '').lower(),
                        ]
                        extract_file.add_flavors({'external': script_flavors})

                        for c in strelka.chunk_string(text):
                            self.upload_to_coordinator(
                                extract_file.pointer,
                                c,
                                self.expire_at,
                            )

                        self.files.append(extract_file)
                        self.event['total']['extracted'] += 1

            for child in node.getchildren():
                self._recurse_node(self, child, xml_args)

        return
