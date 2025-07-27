import io
import logging

import fitz  # PyMuPDF
from PIL import Image, UnidentifiedImageError
from pillow_heif import register_heif_opener

from strelka import strelka

logging.getLogger("PIL").setLevel(logging.WARNING)

# Register HEIF support
register_heif_opener()


class ScanTranscode(strelka.Scanner):
    """
    Converts supported images for easier scanning

    Supports HEIF, HEIC, AVIF (via Pillow) and SVG (via PyMuPDF)
    Typical supported output options: gif webp jpeg bmp png tiff
    """

    def scan(self, data, file, options, expire_at):
        max_file_size = options.get("max_file_size", 5 * 1024 * 1024)  # Default 5MB
        
        # Format-specific output options for optimization
        svg_output_format = options.get("svg_output_format", "png")  # SVG optimized for PNG
        heif_output_format = options.get("heif_output_format", "jpeg")  # HEIF optimized for JPEG  
        avif_output_format = options.get("avif_output_format", "jpeg")  # AVIF optimized for JPEG
        default_output_format = options.get("output_format", "png")  # General fallback
        
        # Check file size limit
        if len(data) > max_file_size:
            self.flags.append("file_too_large")
            self.event["file_size"] = len(data)
            self.event["max_file_size"] = max_file_size
            return

        def convert_with_pillow(im, format_type):
            with io.BytesIO() as f:
                im.save(f, format=f"{format_type}", quality=90)
                return f.getvalue()

        def convert_svg_with_pymupdf(svg_data):
            """Convert SVG using PyMuPDF with format-specific optimization
            
            Note: SVG files are rendered to PNG via PyMuPDF, then optionally 
            converted to svg_output_format if different from PNG
            """
            try:
                # Create a document from SVG data
                doc = fitz.open("svg", svg_data)
                page = doc[0]
                
                # Render page to a pixmap (default is PNG format)
                pix = page.get_pixmap()
                png_data = pix.tobytes("png")
                doc.close()
                
                # If SVG output format is not PNG, convert using Pillow
                if svg_output_format.lower() != "png":
                    img = Image.open(io.BytesIO(png_data))
                    return convert_with_pillow(img, svg_output_format)
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
                output_format = svg_output_format
                input_format = "svg"
            else:
                # Determine output format based on input format
                img = Image.open(io.BytesIO(data))
                if hasattr(img, 'format') and img.format:
                    input_format = img.format.lower()
                    if img.format.upper() in ['HEIF', 'HEIC']:
                        output_format = heif_output_format
                    elif img.format.upper() == 'AVIF':
                        output_format = avif_output_format
                    else:
                        output_format = default_output_format
                else:
                    input_format = "unknown"
                    output_format = default_output_format
                
                converted_image = convert_with_pillow(img, output_format)

            # Create descriptive filename following PDF scanner pattern
            extract_file = strelka.File(
                name=f"transcode_{input_format}_2_{output_format.lower()}",
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