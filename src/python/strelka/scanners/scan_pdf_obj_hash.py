from strelka import strelka
from hashlib import md5
from pdf_object_hashing import pdf_object as po

class ScanPdfObjHash(strelka.Scanner):
    def scan(self, data, file, options, expire_at):
        pdf_object = po(fdata=data)
        if pdf_object:
            obj_hash_str = ""
            pdf_file_hash = pdf_object.sha256
            try:
                pdf_object.check_pdf_header()
                pdf_object.trailer_process()
                pdf_object.trailer_process()
                pdf_object.start_object_parsing()
                pdf_object.pull_objects_xref_aware()
            except:
                self.event["object_hash"] = "error"
            file_ordered_objects = pdf_object.get_objects_by_file_order(in_use_only=True)
            if file_ordered_objects:
                for item in file_ordered_objects:
                    obj_hash_str += item["object_type"] + "|"
                if obj_hash_str:
                    obj_hash = md5(obj_hash_str.encode()).hexdigest()
                    self.event["object_hash"] = obj_hash
                    self.event["hash_string"] = obj_hash_str
                else:
                    self.event["object_hash"] = False
                    self.event["hash_string"] = False

