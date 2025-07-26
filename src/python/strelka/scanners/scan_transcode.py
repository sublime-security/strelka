import io
import logging

import fitz  # PyMuPDF
import pillow_avif
from PIL import Image, UnidentifiedImageError
from pillow_heif import register_heif_opener

from strelka import strelka

logging.getLogger("PIL").setLevel(logging.WARNING)

# Must be imported as a plugin, doesn't need to be used
_ = pillow_avif.AvifImagePlugin

register_heif_opener()


class ScanTranscode(strelka.Scanner):
    """
    Converts supported images for easier scanning

    Supports HEIF, HEIC, AVIF (via Pillow) and SVG (via PyMuPDF)
    Typical supported output options: gif webp jpeg bmp png tiff
    """

    def scan(self, data, file, options, expire_at):
        output_format = options.get("output_format", "jpeg")
        max_file_size = options.get("max_file_size", 5 * 1024 * 1024)  # Default 5MB
        
        # Check file size limit
        if len(data) > max_file_size:
            self.flags.append("file_too_large")
            self.event["file_size"] = len(data)
            self.event["max_file_size"] = max_file_size
            return

        def convert_with_pillow(im):
            with io.BytesIO() as f:
                im.save(f, format=f"{output_format}", quality=90)
                return f.getvalue()

        def convert_svg_with_pymupdf(svg_data):
            """Convert SVG to PNG using PyMuPDF
            
            Note: SVG files are always rendered to PNG first via PyMuPDF,
            then optionally converted to the specified output_format via Pillow
            """
            try:
                # Create a document from SVG data
                doc = fitz.open("svg", svg_data)
                page = doc[0]
                
                # Render page to a pixmap (default is PNG format)
                pix = page.get_pixmap()
                png_data = pix.tobytes("png")
                doc.close()
                
                # If output format is not PNG, convert using Pillow
                if output_format.lower() != "png":
                    img = Image.open(io.BytesIO(png_data))
                    return convert_with_pillow(img)
                else:
                    return png_data
            except Exception:
                raise UnidentifiedImageError("Failed to convert SVG")

        # Check if this is an SVG file
        is_svg = (b'<svg' in data[:1000].lower() or 
                 b'<?xml' in data[:100] and b'<svg' in data[:2000].lower())

        try:
            if is_svg:
                converted_image = convert_svg_with_pymupdf(data)
            else:
                # Use Pillow for other formats (HEIF, HEIC, AVIF, etc.)
                converted_image = convert_with_pillow(Image.open(io.BytesIO(data)))

            # Create extracted file for local Strelka framework
            extract_file = strelka.File(
                name=file.name,
                source=self.name,
            )

            # Upload the converted image data to coordinator
            for chunk in strelka.chunk_string(converted_image):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    chunk,
                    expire_at,
                )

            self.files.append(extract_file)

        except UnidentifiedImageError:
            self.flags.append("unidentified_image")
            return
        except Exception:
            self.flags.append("conversion_error")
            return

        self.flags.append("transcoded")