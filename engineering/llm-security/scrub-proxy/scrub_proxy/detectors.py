"""Detectors. Each returns spans: (start, end, kind, type) with kind in {"SEC", "PII"}."""
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import warnings
from collections import Counter

Span = tuple  # (start, end, kind, type)

# ---------------------------------------------------------------- regexes
_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
REGEXES = [
    ("SEC", "PRIVKEY", re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")),
    ("SEC", "JWT", re.compile(
        r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("SEC", "URLCRED", re.compile(r"(?:(?<=://)|(?<=: //))[^\s/:@'\"]+:[^\s/@'\"]+(?=@)")),
    ("SEC", "ANTHROPIC", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("PII", "EMAIL", re.compile(
        r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")),
    ("PII", "IP", re.compile(rf"(?<![\d.]){_OCT}\.{_OCT}\.{_OCT}\.{_OCT}(?!\.?\d)")),
    ("PII", "CARD", re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")),
    ("PII", "SSN", re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])")),
    ("PII", "PHONE", re.compile(
        r"(?<![\w+.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}(?!\w|[.-]\d)")),
]

EMAIL_ALLOW = re.compile(
    r"^(?:git|noreply|no-reply)@|@(?:example\.(?:com|org|net)|anthropic\.com)$", re.I)


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def _valid(typ: str, v: str) -> bool:
    if typ == "EMAIL":
        return not EMAIL_ALLOW.search(v)
    if typ == "IP":
        return not (v.startswith(("127.", "0.", "255.")) or v.endswith(".0"))
    if typ == "CARD":
        d = re.sub(r"\D", "", v)
        return 13 <= len(d) <= 19 and len(set(d)) > 1 and _luhn(d)
    if typ == "PHONE":
        d = re.sub(r"\D", "", v)
        if not 10 <= len(d) <= 15:
            return False
        # bare space-separated digit runs are usually data, not phones
        return "+" in v or "(" in v or "-" in v or "." in v
    return True


def regex_spans(text: str) -> list:
    out = []
    for kind, typ, rx in REGEXES:
        for m in rx.finditer(text):
            if _valid(typ, m.group(0)):
                out.append((m.start(), m.end(), kind, typ))
    return out


# ---------------------------------------------------------------- entropy
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")


def _entropy(s: str) -> float:
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def entropy_spans(text: str, limit: float = 4.5) -> list:
    out = []
    for m in _TOKEN.finditer(text):
        t = m.group(0).strip("=")
        if len(t) < 20 or re.fullmatch(r"[0-9a-fA-F]+", t):  # hex disabled (git SHAs)
            continue
        classes = sum(bool(re.search(p, t)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
        if classes < 3 or "/" in t and t.count("/") > 2:  # needs mixed charset; skip paths
            continue
        if _entropy(t) >= limit:
            out.append((m.start(), m.end(), "SEC", "ENTROPY"))
    return out


# ---------------------------------------------------------------- detect-secrets
_DS_SKIP = {"HexHighEntropyString", "Base64HighEntropyString", "IPPublicDetector",
            "PrivateKeyDetector"}
_ds_plugins = None


def _ds_config():
    global _ds_plugins
    if _ds_plugins is None:
        from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
        _ds_plugins = [{"name": c.__name__} for c in get_mapping_from_secret_type_to_class().values()
                       if c.__name__ not in _DS_SKIP]
    return _ds_plugins


def ds_spans(text: str) -> list:
    from detect_secrets.core.scan import scan_line
    from detect_secrets.settings import transient_settings
    out = []
    with transient_settings({"plugins_used": _ds_config()}):
        pos = 0
        for line in text.splitlines(keepends=True):
            if len(line) < 6000:  # pathological minified lines: left to regex/gitleaks
                for s in scan_line(line.rstrip("\n")):
                    v = s.secret_value
                    if not v or len(v) < 4:
                        continue
                    typ = re.sub(r"[^A-Z0-9]", "", s.type.upper())[:20] or "SECRET"
                    i = line.find(v)
                    while i != -1:
                        out.append((pos + i, pos + i + len(v), "SEC", typ))
                        i = line.find(v, i + 1)
            pos += len(line)
    return out


# ---------------------------------------------------------------- gitleaks
class Gitleaks:
    def __init__(self, path: str | None = None):
        self.path = path or shutil.which("gitleaks") or os.path.expanduser("~/.local/bin/gitleaks")
        if not os.access(self.path, os.X_OK):
            raise RuntimeError(f"gitleaks not found at {self.path}")

    def values(self, texts: list[str]) -> list[tuple[str, str]]:
        """Run once over all texts; return (secret, type) pairs."""
        if not texts:
            return []
        blob = "\n\x00GITLEAKS-SEP\x00\n".join(texts)
        p = subprocess.run(
            [self.path, "stdin", "--no-banner", "--log-level", "error", "-f", "json",
             "-r", "-", "--exit-code", "0"],
            input=blob.encode(), capture_output=True, timeout=120,
        )
        if p.returncode != 0:
            raise RuntimeError(f"gitleaks failed rc={p.returncode}: {p.stderr[:300]!r}")
        found = json.loads(p.stdout or b"[]") or []
        out = []
        for f in found:
            v = f.get("Secret") or f.get("Match") or ""
            if len(v) >= 4:
                out.append((v, re.sub(r"[^A-Z0-9]", "", f["RuleID"].upper())[:20] or "SECRET"))
        return out


def occurrences(text: str, pairs) -> list:
    out = []
    for v, typ in pairs:
        i = text.find(v)
        while i != -1:
            out.append((i, i + len(v), "SEC", typ))
            i = text.find(v, i + 1)
    return out


# ---------------------------------------------------------------- GLiNER
NER_STOP = {
    "claude", "anthropic", "claude code", "python", "linux", "github", "todo", "readme",
    "name", "person", "full name", "address", "street address", "user", "username", "null",
    "none", "true", "false", "ubuntu", "ollama", "docker", "google", "microsoft", "apple",
}
_NAME_BAD = re.compile(r"[_(){}\[\]=<>/\\;:\"`|$#@*0-9.]")


def chunk_text(text: str, size: int = 1000):
    """Yield (offset, chunk) at line boundaries; long lines split at whitespace."""
    buf, start, pos = [], 0, 0
    for line in text.splitlines(keepends=True):
        while len(line) > size:
            cut = line.rfind(" ", 0, size)
            cut = cut if cut > size // 2 else size
            if buf:
                yield start, "".join(buf)
                buf = []
            yield pos, line[:cut]
            pos += cut
            line = line[cut:]
            start = pos
        if sum(map(len, buf)) + len(line) > size and buf:
            yield start, "".join(buf)
            buf, start = [], pos
        buf.append(line)
        pos += len(line)
    if buf:
        yield start, "".join(buf)


class NER:
    # Only the PyTorch weights and tokenizer files are used. Fetching just these keeps the
    # cache ~640 MB instead of ~1.8 GB (the repo also ships three ONNX copies), and loading
    # from a local path avoids GLiNER's whole-repo completeness check.
    FILES = ["*.json", "*.bin", "*.model", "*.txt", "*.safetensors"]

    @classmethod
    def _local_path(cls, model_id: str) -> str:
        if os.path.isdir(model_id):
            return model_id
        from huggingface_hub import snapshot_download
        kw = dict(allow_patterns=cls.FILES, ignore_patterns=["onnx/*"])
        try:
            return snapshot_download(model_id, local_files_only=True, **kw)
        except Exception:  # not cached yet: one-time download of just those files
            return snapshot_download(model_id, **kw)

    # label -> (placeholder type, threshold)
    LABELS = {"name": ("NAME", 0.6), "street address": ("ADDRESS", 0.6)}

    def __init__(self, model_id: str, store, threads: int = 4):
        warnings.filterwarnings("ignore")
        import torch
        from gliner import GLiNER
        torch.set_num_threads(threads)
        self.model = GLiNER.from_pretrained(self._local_path(model_id))
        self.store = store
        self.sig = hashlib.sha256(f"{model_id}|{sorted(self.LABELS.items())}|v1".encode()).hexdigest()[:16]

    @staticmethod
    def _skip(chunk: str) -> bool:
        if not re.search(r"[A-Z]", chunk):
            return True  # names/addresses we accept need a capital
        ws = sum(c.isspace() for c in chunk)
        return ws / max(len(chunk), 1) < 0.03  # base64 blobs, minified code

    def _keep(self, typ: str, v: str, score: float) -> bool:
        if v.lower() in NER_STOP or len(v) < 3:
            return False
        if typ == "NAME":
            if _NAME_BAD.search(v) or not re.search(r"[A-Z]", v) or v.isupper():
                return False
            return len(v.split()) >= 2 or score >= 0.85
        if typ == "ADDRESS":
            return bool(re.search(r"\d", v) and re.search(r"[A-Za-z]{3}", v) and " " in v and len(v) >= 8)
        return True

    def spans(self, text: str) -> list:
        out = []
        labels = list(self.LABELS)
        lo = min(t for _, t in self.LABELS.values())
        for off, chunk in chunk_text(text):
            if self._skip(chunk):
                continue
            key = "ner:" + self.sig + hashlib.sha256(chunk.encode()).hexdigest()
            ents = self.store.cache_get(key)
            if ents is None:
                ents = [
                    [e["start"], e["end"], e["label"], e["score"]]
                    for e in self.model.predict_entities(chunk, labels, threshold=lo)
                ]
                self.store.cache_set(key, ents)
            for s, e, label, score in ents:
                typ, thr = self.LABELS[label]
                raw = chunk[s:e]
                v = raw.strip(" \t\r\n,.;:'\"")
                if score < thr or not v or not self._keep(typ, v, score):
                    continue
                s += raw.find(v)
                out.append((off + s, off + s + len(v), "PII", typ))
        return out
