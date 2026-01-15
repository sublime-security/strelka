from typing import Dict, Any
from strelka import strelka
from hashlib import md5
from pdf_object_hashing import pdf_object as po

class ScanPdfObjHash(strelka.Scanner):
    def scan(self, data: bytes, file: strelka.File, options: Dict[str, Any], expire_at: int) -> None:
        pdf_object = po(fdata=data)
        if pdf_object:
            obj_hash_str = ""
            object_threshold = options.get("object_threshold")
            obj_count = data.count(b' obj')
            if object_threshold is None or obj_count < object_threshold:
                try:
                    pdf_object.check_pdf_header()
                    pdf_object.trailer_process()
                    pdf_object.start_object_parsing()
                    pdf_object.pull_objects_xref_aware()
                    file_ordered_objects = pdf_object.get_objects_by_file_order(in_use_only=True)
                    if file_ordered_objects:
                        for item in file_ordered_objects:
                            obj_hash_str += item["object_type"] + "|"
                        if obj_hash_str:
                            obj_hash = md5(obj_hash_str.encode()).hexdigest()
                            self.event["object_hash"] = obj_hash
                            self.event["hash_string"] = obj_hash_str
                        else:
                            self.event["object_hash"] = "no_objects_parsed"
                            self.event["hash_string"] = "no_objects_parsed"
                except Exception:
                    self.event["object_hash"] = "error"
