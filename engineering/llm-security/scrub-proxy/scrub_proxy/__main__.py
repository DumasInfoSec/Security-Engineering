"""CLI: serve | scan FILE | scan-image IN OUT | lookup PLACEHOLDER | stats

Environment:
  SCRUB_PORT (8787)  SCRUB_UPSTREAM (https://api.anthropic.com)
  SCRUB_DATA_DIR (~/.local/share/scrub-proxy)
  SCRUB_NER_MODEL (knowledgator/gliner-pii-base-v1.0)  SCRUB_NER=0 disables NER
  SCRUB_IMAGES=0 disables image OCR (images are then refused)
  SCRUB_OCR_MAX_SIDE (3000)  longest side OCR runs at
  SCRUB_ALLOW_BINARY=1 forwards PDFs and URL/file-id images unscanned
  SCRUB_PASSTHROUGH_POST=/path,/path  extra POST paths forwarded unscrubbed
  $DATA_DIR/always.json  {"value": "TYPE"} always scrubbed (e.g. your real name)
  $DATA_DIR/allow.txt    one value per line never scrubbed
"""
import json
import logging
import os
import sys


def build():
    from .detectors import NER, Gitleaks
    from .scrubber import Scrubber
    from .store import Store
    data_dir = os.path.expanduser(os.environ.get("SCRUB_DATA_DIR", "~/.local/share/scrub-proxy"))
    store = Store(data_dir)
    always, allow = {}, set()
    p = os.path.join(data_dir, "always.json")
    if os.path.exists(p):
        always = json.load(open(p))
    p = os.path.join(data_dir, "allow.txt")
    if os.path.exists(p):
        allow = {ln.rstrip("\n") for ln in open(p) if ln.strip()}
    ner = None
    if os.environ.get("SCRUB_NER", "1") != "0":
        ner = NER(os.environ.get("SCRUB_NER_MODEL", "knowledgator/gliner-pii-base-v1.0"), store)
    images = None
    if os.environ.get("SCRUB_IMAGES", "1") != "0":
        from .images import ImageScrubber
        images = ImageScrubber(store)
    return Scrubber(store, ner=ner, gitleaks=Gitleaks(), images=images,
                    allow_binary=os.environ.get("SCRUB_ALLOW_BINARY") == "1",
                    always=always, allow=allow)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        from aiohttp import web
        from .server import Proxy
        s = build()
        paths = {p for p in os.environ.get("SCRUB_PASSTHROUGH_POST", "").split(",") if p}
        proxy = Proxy(s, os.environ.get("SCRUB_UPSTREAM", "https://api.anthropic.com"), paths)
        web.run_app(proxy.app(), host="127.0.0.1", port=int(os.environ.get("SCRUB_PORT", "8787")))
    elif cmd == "scan":
        s = build()
        text = open(sys.argv[2]).read() if len(sys.argv) > 2 else sys.stdin.read()
        print(s.scrub_texts([text])[0])
    elif cmd == "scan-image":
        import base64, mimetypes
        from collections import Counter
        s = build()
        mt = mimetypes.guess_type(sys.argv[2])[0] or "image/png"
        block = {"type": "image", "source": {"type": "base64", "media_type": mt,
                 "data": base64.b64encode(open(sys.argv[2], "rb").read()).decode()}}
        stats = Counter()
        s.scrub_texts([], stats, [block])
        open(sys.argv[3], "wb").write(base64.b64decode(block["source"]["data"]))
        print(dict(stats) or "nothing found", "->", sys.argv[3])
    elif cmd == "lookup":
        from .store import Store
        st = Store(os.path.expanduser(os.environ.get("SCRUB_DATA_DIR", "~/.local/share/scrub-proxy")))
        print(st.lookup(sys.argv[2]))
    elif cmd == "stats":
        from .store import Store
        st = Store(os.path.expanduser(os.environ.get("SCRUB_DATA_DIR", "~/.local/share/scrub-proxy")))
        print(json.dumps(st.stats(), indent=2))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
