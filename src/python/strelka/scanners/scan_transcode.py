import io
import logging

import fitz  # PyMuPDF
from PIL import Image, UnidentifiedImageError
import pi_heif

from strelka import strelka

logging.getLogger("PIL").setLevel(logging.WARNING)

# Register HEIF support
pi_heif.register_heif_opener()


class ScanTranscode(strelka.Scanner):
    """Converts modern image formats to standard formats for analysis.

    Supports HEIF, HEIC, AVIF, and SVG conversion to PNG/JPEG.
    Enables downstream OCR, QR code detection, and image analysis.
    """

    def scan(self, data, file, options, expire_at):
        max_file_size = options.get("max_file_size", 5 * 1024 * 1024)  # Default 5MB
        
        # Format-specific output options
        svg_output_format = options.get("svg_output_format", "png")
        heif_output_format = options.get("heif_output_format", "jpeg")
        avif_output_format = options.get("avif_output_format", "jpeg")
        default_output_format = options.get("output_format", "png")
        
        # Check file size limit
        if len(data) > max_file_size:
            self.flags.append("file_too_large")
            self.event["file_size"] = len(data)
            self.event["max_file_size"] = max_file_size
            return

        def convert_image(im, format_type):
            """Convert PIL Image to specified format."""
            with io.BytesIO() as f:
                im.save(f, format=format_type.upper(), quality=90)
                return f.getvalue()

        def convert_svg(svg_data):
            """Convert SVG to raster format using PyMuPDF."""
            try:
                doc = fitz.open("svg", svg_data)
                page = doc[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(1.0, 1.0))
                png_data = pix.tobytes("png")
                doc.close()
                
                if svg_output_format.lower() != "png":
                    img = Image.open(io.BytesIO(png_data))
                    return convert_image(img, svg_output_format)
                else:
                    return png_data
            except Exception:
                raise UnidentifiedImageError("Failed to convert SVG")

        def detect_format(data):
            """Detect image format from file header."""
            header = data[:100].lower()
            if b'<svg' in header:
                return "svg"
            if b'<?xml' in header and b'<svg' in data[:500].lower():
                return "svg"
            return None

        # Detect format from file header
        detected_format = detect_format(data)

        try:
            if detected_format == "svg":
                converted_image = convert_svg(data)
                output_format = svg_output_format
                input_format = "svg"
            else:
                img = Image.open(io.BytesIO(data))
                
                if hasattr(img, 'format') and img.format:
                    input_format = img.format.lower()
                    img_format_upper = img.format.upper()
                    
                    if img_format_upper in ['HEIF', 'HEIC']:
                        # Use PNG for RGBA images (faster, supports transparency)
                        output_format = 'png' if img.mode == 'RGBA' else heif_output_format
                    elif img_format_upper == 'AVIF':
                        output_format = 'png' if img.mode == 'RGBA' else avif_output_format
                    else:
                        output_format = 'png' if img.mode == 'RGBA' else default_output_format
                        
                    # Track when we auto-switch to PNG for RGBA
                    if img.mode == 'RGBA' and output_format == 'png':
                        self.flags.append("auto_switched_to_png")
                else:
                    input_format = "unknown"
                    output_format = default_output_format
                
                converted_image = convert_image(img, output_format)

            # Create output file
            extract_file = strelka.File(
                name=f"transcode_{input_format}_2_{output_format.lower()}",
                source=self.name,
            )

            # Upload converted image data
            for chunk in strelka.chunk_string(converted_image):
                self.upload_to_coordinator(
                    extract_file.pointer,
                    chunk,
                    expire_at,
                )

            self.files.append(extract_file)
            
            # Add conversion metadata
            self.event["input_format"] = input_format
            self.event["output_format"] = output_format

        except UnidentifiedImageError:
            self.flags.append("unidentified_image")
            return
        except Exception:
            self.flags.append("conversion_error")
            return

        self.flags.append("transcoded")