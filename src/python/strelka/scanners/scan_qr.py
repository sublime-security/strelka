import io
import re
from pathlib import Path
from typing import Any

import cv2
import fitz
import numpy as np
from numpy.typing import NDArray
from PIL import Image
from strelka import strelka
import zxingcpp

URL_REGEX = r'^[a-zA-Z]{3,10}:\/\/.*'

_WECHAT_MODELS_DIR = Path("/opt/strelka/models/wechat_qrcode")
_ZXING_FORMATS = zxingcpp.BarcodeFormats(zxingcpp.BarcodeFormat.QRCode)

ASPECT_RATIO_LOWER_BOUND = 0.75
ASPECT_RATIO_UPPER_BOUND = 1.33
ASPECT_RATIO_MAX_NORMALISED_DIM = 1024


def _zxing_decode(arr: NDArray[Any]) -> set[str]:
    results = zxingcpp.read_barcodes(arr, formats=_ZXING_FORMATS, try_rotate=True)
    return {r.text for r in results if r.text}


def _wechat_decode(bgr: NDArray[Any], detector: cv2.wechat_qrcode.WeChatQRCode) -> set[str]:
    texts, _ = detector.detectAndDecode(bgr)
    return {t for t in texts if t}


def _preprocess_variants(bgr: NDArray[Any]) -> list[NDArray[Any]]:
    variants: list[NDArray[Any]] = []

    variants.extend(cv2.split(bgr))

    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)

    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    variants.append(clahe.apply(gray))

    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(otsu)

    variants.append(255 - bgr)

    # Recover QR codes rendered with heavily squished proportions
    h, w = bgr.shape[:2]
    aspect = w / h
    if aspect < ASPECT_RATIO_LOWER_BOUND or aspect > ASPECT_RATIO_UPPER_BOUND:
        sq = min(max(h, w), ASPECT_RATIO_MAX_NORMALISED_DIM)
        normalized = cv2.resize(bgr, (sq, sq), interpolation=cv2.INTER_LINEAR)
        variants.append(normalized)
        if sq < 512:
            variants.append(cv2.resize(normalized, (512, 512), interpolation=cv2.INTER_CUBIC))

    if max(h, w) < 512:
        scale = 512 / max(h, w)
        variants.append(cv2.resize(bgr, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC))

    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    sat_mask = (hsv[:, :, 1] > 100).astype(np.uint8) * 255
    sat_pixels = cv2.findNonZero(sat_mask)
    if sat_pixels is not None:
        bx, by, bw, bh = cv2.boundingRect(sat_pixels)
        if bw * bh < 0.8 * h * w and min(bw, bh) > 50:
            pad = 10
            crop = bgr[max(0, by - pad) : by + bh + pad, max(0, bx - pad) : bx + bw + pad]
            variants.extend(cv2.split(crop))

    return variants


def _decode_qr(img: Image.Image, detector: cv2.wechat_qrcode.WeChatQRCode) -> set[str]:
    rgb = np.asarray(img.convert("RGB"), dtype=np.uint8)

    results = _zxing_decode(rgb)
    if results:
        return results

    bgr = rgb[:, :, ::-1]

    results = _wechat_decode(bgr, detector)
    if results:
        return results

    for variant in _preprocess_variants(bgr):
        if variant.ndim == 2:
            variant = cv2.cvtColor(variant, cv2.COLOR_GRAY2BGR)

        results = _zxing_decode(variant)
        if results:
            return results

        results = _wechat_decode(variant, detector)
        if results:
            return results

    return set()


class ScanQr(strelka.Scanner):
    """
    Collects QR code metadata from image files.
    """

    def init(self):
        self.detector = cv2.wechat_qrcode.WeChatQRCode(
            str(_WECHAT_MODELS_DIR / "detect.prototxt"),
            str(_WECHAT_MODELS_DIR / "detect.caffemodel"),
            str(_WECHAT_MODELS_DIR / "sr.prototxt"),
            str(_WECHAT_MODELS_DIR / "sr.caffemodel"),
        )

    def scan(self, data, file, options, expire_at):
        pdf_to_png = options.get('pdf_to_png', False)

        try:
            if pdf_to_png and 'application/pdf' in file.flavors.get('mime', []):
                doc = fitz.open(stream=data, filetype='pdf')
                data = doc.get_page_pixmap(0, dpi=150).tobytes()

            img = Image.open(io.BytesIO(data))
            decoded = _decode_qr(img, self.detector)

            if not decoded:
                return

            text = next(iter(decoded))
            self.event['data'] = text

            if any(qtype in text for qtype in ['MATMSG', 'mailto']):
                self.event['type'] = 'email'
            elif any(qtype in text for qtype in ['tel:', 'sms:']):
                self.event['type'] = 'mobile'
            elif 'geo:' in text:
                self.event['type'] = 'geo'
            elif 'WIFI' in text:
                self.event['type'] = 'wifi'
            elif re.match(URL_REGEX, text):
                self.event['type'] = 'url'
            else:
                self.event['type'] = 'undefined'

        except Exception:
            self.flags.append('general error')
