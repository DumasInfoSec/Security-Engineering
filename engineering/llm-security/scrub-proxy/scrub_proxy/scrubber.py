"""Request scrubbing and response restoration."""
import hashlib
import json
import re
from collections import Counter

from . import detectors as D
from .store import PH_RE, Store


PROXY_NOTE = (
    "Some values in this conversation appear as tokens like PII_EMAIL_xxxxxxxx or "
    "SEC_GITHUBPAT_xxxxxxxx (8 hex chars). A local proxy swaps them with the real values in both "
    "directions, so the user sees real values and tool calls receive them. Treat each token "
    "as the real value: copy it verbatim and whole into replies and tool inputs, never "
    "slice, reformat or guess at it, and do not describe it as redacted or a placeholder. "
    "In images, a black box labelled with such a token stands for that value: read the label "
    "as the value and do not mention the box.")


class BlockedContent(Exception):
    """Content the proxy cannot scan; refused rather than forwarded."""


class LeakGuardError(Exception):
    pass


# Block types forwarded untouched. thinking/redacted_thinking carry signatures over the
# exact text and were never restored, so they only contain placeholders already.
PASS_BLOCKS = {"thinking", "redacted_thinking", "server_tool_use", "web_search_tool_result",
               "web_fetch_tool_result", "code_execution_tool_result", "container_upload"}
BINARY_BLOCKS = {"image", "document"}

_PARTIAL = re.compile(
    r"(?:P(?:I(?:I(?:_(?:[A-Z0-9]{1,20}(?:_[0-9a-f]{0,7})?)?)?)?)?"
    r"|S(?:E(?:C(?:_(?:[A-Z0-9]{1,20}(?:_[0-9a-f]{0,7})?)?)?)?)?)"
)
_MAX_PARTIAL = 3 + 1 + 20 + 1 + 7


def _skeleton(obj, depth=0):
    """Structure without values, safe to log."""
    if depth > 4:
        return "..."
    if isinstance(obj, dict):
        return {k: (v if k == "type" else _skeleton(v, depth + 1)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_skeleton(v, depth + 1) for v in obj[:3]]
    return type(obj).__name__


class Scrubber:
    def __init__(self, store: Store, ner=None, gitleaks=None, allow_binary=False,
                 always: dict | None = None, allow: set | None = None, images=None):
        self.store = store
        self.images = images  # ImageScrubber or None (then images are refused)
        self.ner = ner
        self.gitleaks = gitleaks
        self.allow_binary = allow_binary
        self.allow = allow or set()
        # user-supplied values that must always be scrubbed, e.g. {"Jane Doe": "NAME"}
        for v, typ in (always or {}).items():
            store.placeholder_for("PII", typ, v)
        parts = [bool(ner) and ner.sig, bool(gitleaks), "v1"]
        self.sig = hashlib.sha256(repr(parts).encode()).hexdigest()[:16]

    # ---------------------------------------------------------- detection
    def detect(self, texts: list[str]) -> list[list]:
        keys = ["det:" + self.sig + hashlib.sha256(t.encode()).hexdigest() for t in texts]
        results = [self.store.cache_get(k) for k in keys]
        miss = [i for i, r in enumerate(results) if r is None]
        if miss:
            leaks = self.gitleaks.values([texts[i] for i in miss]) if self.gitleaks else []
            for i in miss:
                t = texts[i]
                spans = D.regex_spans(t) + D.entropy_spans(t) + D.ds_spans(t)
                spans += D.occurrences(t, leaks)
                if self.ner:
                    spans += self.ner.spans(t)
                results[i] = [list(s) for s in spans]
                self.store.cache_set(keys[i], results[i])
        return results

    def _known_spans(self, text: str) -> list:
        rx = self.store.known_regex()
        if not rx:
            return []
        out = []
        for m in rx.finditer(text):
            ph = self.store.by_val[m.group(0)]
            kind, typ = ph.split("_")[0], self.store.types[m.group(0)]
            out.append((m.start(), m.end(), kind, typ))
        return out

    def _apply(self, text: str, spans: list, stats: Counter) -> str:
        spans = [tuple(s) for s in spans] + self._known_spans(text)
        phs = [(m.start(), m.end()) for m in PH_RE.finditer(text)]
        spans = [
            s for s in spans
            if s[1] > s[0] and text[s[0]:s[1]] not in self.allow
            and not any(s[0] < pe and ps < s[1] for ps, pe in phs)
        ]
        if not spans:
            return text
        spans.sort(key=lambda s: (s[0], -s[1]))
        merged = [list(spans[0])]
        for s, e, kind, typ in spans[1:]:
            cur = merged[-1]
            if s < cur[1]:  # overlap: take the union so no fragment leaks
                if kind == "SEC" and cur[2] == "PII":
                    cur[2], cur[3] = kind, typ
                cur[1] = max(cur[1], e)
            else:
                merged.append([s, e, kind, typ])
        out, last = [], 0
        for s, e, kind, typ in merged:
            v = text[s:e]
            out.append(text[last:s])
            out.append(self.store.placeholder_for(kind, typ, v))
            stats[typ] += 1
            last = e
        out.append(text[last:])
        return "".join(out)

    def scrub_texts(self, texts: list[str], stats: Counter | None = None,
                    images: list | None = None) -> list[str]:
        stats = stats if stats is not None else Counter()
        detected = self.detect(texts)
        # Register every detected value across the whole batch first, so a value revealed
        # in one block (e.g. `password = "x"` in a tool result) is also scrubbed in blocks
        # processed earlier where nothing marks it as a secret.
        for t, spans in zip(texts, detected):
            for s, e, kind, typ in spans:
                v = t[s:e]
                if e > s and v not in self.allow and not PH_RE.search(v):
                    self.store.placeholder_for(kind, typ, v)
        # Images after text registration (so text-revealed values are blacked out in images)
        # and before text replacement (so values read from images are scrubbed in text).
        for b in images or []:
            self.images.scrub_block(b, self, stats)
        return [self._apply(t, sp, stats) for t, sp in zip(texts, detected)]

    # ---------------------------------------------------------- request walk
    def _collect(self, body: dict) -> tuple[list, list]:
        """Return (container, key) slots holding strings, and image blocks to scrub."""
        slots, images = [], []

        def walk_json(obj):  # tool_use inputs: every string value
            items = obj.items() if isinstance(obj, dict) else enumerate(obj)
            for k, v in items:
                if isinstance(v, str):
                    slots.append((obj, k))
                elif isinstance(v, (dict, list)):
                    walk_json(v)

        def walk_desc(obj):  # tool definitions: description strings only
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "description" and isinstance(v, str):
                        slots.append((obj, k))
                    else:
                        walk_desc(v)
            elif isinstance(obj, list):
                for v in obj:
                    walk_desc(v)

        def blocks(container, key):
            content = container.get(key)
            if isinstance(content, str):
                slots.append((container, key))
                return
            if not isinstance(content, list):
                return
            for b in content:
                t = b.get("type")
                if t == "text":
                    slots.append((b, "text"))
                elif t == "tool_result":
                    blocks(b, "content")
                elif t == "tool_use":
                    walk_json(b.get("input") or {})
                elif t == "document" and (b.get("source") or {}).get("type") == "text":
                    slots.append((b["source"], "data"))
                    for k in ("title", "context"):
                        if isinstance(b.get(k), str):
                            slots.append((b, k))
                elif t == "image" and self.images and (b.get("source") or {}).get("type") == "base64":
                    images.append(b)
                elif t in BINARY_BLOCKS:
                    if not self.allow_binary:
                        raise BlockedContent(
                            f"{t} block ({(b.get('source') or {}).get('type')}) cannot be scanned; "
                            "attach images as base64, or set SCRUB_ALLOW_BINARY=1 to forward unscanned")
                elif t == "tool_addition":  # deferred tool definitions delivered in-message
                    walk_desc(b.get("tool"))
                elif t in PASS_BLOCKS:
                    continue
                else:
                    raise BlockedContent(f"unknown content block type {t!r}: {_skeleton(b)}")

        if "system" in body:
            blocks(body, "system")
        for msg in body.get("messages", []):
            blocks(msg, "content")
        walk_desc(body.get("tools", []))
        return slots, images

    def scrub_request(self, body: dict, note: bool = True) -> tuple[dict, Counter]:
        stats = Counter()
        slots, images = self._collect(body)
        new = self.scrub_texts([c[k] for c, k in slots], stats, images)
        for (c, k), v in zip(slots, new):
            c[k] = v
        if note and "messages" in body:
            sysp = body.get("system")
            if isinstance(sysp, str):
                body["system"] = [{"type": "text", "text": sysp}] if sysp else []
            body.setdefault("system", [])
            body["system"].append({"type": "text", "text": PROXY_NOTE})
        return body, stats

    def guard(self, data: bytes) -> None:
        """Final check on the serialized outbound body: no known value may survive."""
        rx = self.store.guard_regex()
        if rx:
            m = rx.search(data.decode("utf-8", "replace"))
            if m:
                ph = self.store.by_val.get(m.group(0), "?")
                raise LeakGuardError(f"known value ({ph.rsplit('_', 1)[0]}) present after scrub")

    # ---------------------------------------------------------- restore
    def restore_text(self, s: str, json_escape: bool = False) -> str:
        def rep(m):
            v = self.store.lookup(m.group(0))
            if v is None:
                return m.group(0)
            return json.dumps(v, ensure_ascii=False)[1:-1] if json_escape else v
        return PH_RE.sub(rep, s)

    def restore_obj(self, obj):
        if isinstance(obj, str):
            return self.restore_text(obj)
        if isinstance(obj, list):
            return [self.restore_obj(v) for v in obj]
        if isinstance(obj, dict):
            return {self.restore_text(k): self.restore_obj(v) for k, v in obj.items()}
        return obj

    def restore_message(self, msg: dict) -> dict:
        for b in msg.get("content") or []:
            if b.get("type") == "text":
                b["text"] = self.restore_text(b["text"])
            elif b.get("type") == "tool_use":
                b["input"] = self.restore_obj(b.get("input"))
        return msg


class StreamRestorer:
    """Restores placeholders in a stream of deltas, holding back possible prefixes."""

    def __init__(self, scrubber: Scrubber, json_escape: bool):
        self.s = scrubber
        self.json_escape = json_escape
        self.buf = ""

    def feed(self, piece: str) -> str:
        self.buf += piece
        b = self.buf
        hold = len(b)
        for i in range(max(0, len(b) - _MAX_PARTIAL), len(b)):
            if b[i] in "PS" and _PARTIAL.fullmatch(b, i):
                hold = i
                break
        emit, self.buf = b[:hold], b[hold:]
        return self.s.restore_text(emit, self.json_escape)

    def flush(self) -> str:
        emit, self.buf = self.buf, ""
        return self.s.restore_text(emit, self.json_escape)
