import base64
import io
import json
from collections import Counter

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from rapidfuzz import fuzz

from conftest import PLANTS
from scrub_proxy.scrubber import BlockedContent, Scrubber
from scrub_proxy.store import Store

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
IMG_PLANTS = ["urlpw", "gh", "aws", "name", "email", "phone", "address"]
LINES = [
    "$ cat .env",
    f"DATABASE_URL=postgres://admin:{PLANTS['urlpw']}@db.internal:5432/prod",
    f"GITHUB_TOKEN={PLANTS['gh']}",
    f"AWS_ACCESS_KEY_ID={PLANTS['aws']}",
    f"Owner: {PLANTS['name']} <{PLANTS['email']}>",
    f"Call {PLANTS['phone']} or ship to {PLANTS['address']}",
    "def get_user(user_id): return db.query(User).first()",
]


def render(lines, size=(1300, 330)):
    im = Image.new("RGB", size, (30, 30, 30))
    d = ImageDraw.Draw(im)
    f = ImageFont.truetype(FONT, 22)
    for i, l in enumerate(lines):
        d.text((20, 20 + i * 42), l, font=f, fill=(220, 220, 220))
    return im


def photo(im):
    """Simulate a phone photo of a screen: rotation, blur, noise, JPEG, GPS EXIF."""
    ph = Image.new("RGB", (1800, 900), (90, 80, 70))
    ph.paste(im.resize((1500, 380)), (150, 250))
    ph = ph.rotate(4, resample=Image.BICUBIC, fillcolor=(90, 80, 70)).filter(ImageFilter.GaussianBlur(1.2))
    a = np.asarray(ph).astype(np.int16) + np.random.default_rng(0).normal(0, 10, (900, 1800, 3)).astype(np.int16)
    out = Image.fromarray(a.clip(0, 255).astype(np.uint8))
    exif = Image.Exif()
    exif[0x010F] = "PhoneMaker"
    exif.get_ifd(0x8825)[2] = (51.0, 30.0, 0.0)  # GPSLatitude
    return out, exif


def block(im, fmt="PNG", exif=None):
    buf = io.BytesIO()
    im.save(buf, fmt, **({"exif": exif} if exif else {}))
    mt = "image/jpeg" if fmt == "JPEG" else "image/png"
    return {"type": "image", "source": {"type": "base64", "media_type": mt,
                                        "data": base64.b64encode(buf.getvalue()).decode()}}


def ocr_text(scrubber, b) -> str:
    raw = base64.b64decode(b["source"]["data"])
    res, _ = scrubber.images.ocr(raw)
    return "\n".join(r[1] for r in res or [])


def leaked_in_ocr(text, keys):
    """Fuzzy: OCR of the output must not contain anything close to a planted value."""
    low = text.lower()
    return [k for k in keys if fuzz.partial_ratio(PLANTS[k].lower(), low) >= 80]


@pytest.mark.parametrize("kind", ["screenshot", "photo"])
def test_image_redacted(scrubber, kind):
    im = render(LINES)
    b = block(im) if kind == "screenshot" else block(*photo(im)[:1], fmt="JPEG", exif=photo(im)[1])
    stats = Counter()
    scrubber.scrub_texts([], stats, [b])
    text = ocr_text(scrubber, b)
    assert leaked_in_ocr(text, IMG_PLANTS) == [], text
    assert "get_user" in text and "cat" in text  # non-sensitive content survives
    assert any(k.startswith("IMG_") for k in stats)


def test_exif_gps_stripped(scrubber):
    im, exif = photo(render(["nothing secret here"]))
    b = block(im, "JPEG", exif)
    assert Image.open(io.BytesIO(base64.b64decode(b["source"]["data"]))).getexif()
    scrubber.scrub_texts([], Counter(), [b])
    out = Image.open(io.BytesIO(base64.b64decode(b["source"]["data"])))
    assert not out.getexif() and b["source"]["media_type"] == "image/jpeg"


def test_value_revealed_in_text_blacked_out_in_image(scrubber, tmp_path):
    fresh = Scrubber(Store(str(tmp_path)), ner=scrubber.ner, gitleaks=scrubber.gitleaks,
                     images=scrubber.images)
    b = block(render([f"note to self: {PLANTS['pw']}  (rotate monthly)"], (900, 80)))
    req = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": f'password = "{PLANTS["pw"]}"'}, b]}]}
    fresh.scrub_request(req)
    text = ocr_text(fresh, b)
    assert PLANTS["pw"] not in text and "rotate monthly" in text, text


def test_value_read_from_image_scrubbed_in_text(scrubber, tmp_path):
    """A value only the image's context marks as secret must also vanish from plain text."""
    fresh = Scrubber(Store(str(tmp_path)), ner=scrubber.ner, gitleaks=scrubber.gitleaks,
                     images=scrubber.images)
    pw = "Tr0ub4dorKx"
    # control: on its own, the text mention is not detected
    assert pw in fresh.scrub_texts([f"is {pw} still valid?"])[0]
    b = block(render([f'password = "{pw}"'], (700, 80)))
    req = {"messages": [{"role": "user", "content": [b, {"type": "text", "text": f"is {pw} still valid?"}]}]}
    body, _ = fresh.scrub_request(req)
    assert pw not in json.dumps(body)


def test_image_output_deterministic(scrubber):
    b1, b2 = block(render(LINES)), block(render(LINES))
    scrubber.scrub_texts([], Counter(), [b1])
    scrubber.scrub_texts([], Counter(), [b2])
    assert b1["source"]["data"] == b2["source"]["data"]  # prompt cache stays valid


@pytest.mark.parametrize("b", [
    {"type": "image", "source": {"type": "url", "url": "https://example.com/x.png"}},
    {"type": "image", "source": {"type": "file", "file_id": "file_123"}},
    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "bm90IGFuIGltYWdl"}},
    {"type": "image", "source": {"type": "base64", "media_type": "image/tiff", "data": "AAAA"}},
])
def test_unscannable_images_fail_closed(scrubber, b):
    with pytest.raises(BlockedContent):
        scrubber.scrub_request({"messages": [{"role": "user", "content": [b]}]})
