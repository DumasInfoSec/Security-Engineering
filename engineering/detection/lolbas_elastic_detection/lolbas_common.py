"""Shared helpers for the lolbas scripts. Python 3.6+, stdlib only."""
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

BINARIES_INDEX = "lolbas-binaries"
COMMANDS_INDEX = "lolbas-commands"


def load_config():
    """read KEY=VALUE lines from config.env. anything already exported wins"""
    path = os.path.join(HERE, "config.env")
    if not os.path.exists(path):
        return
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def setting(name, default=None):
    value = os.environ.get(name, default)
    if not value:
        sys.exit("ERROR: %s is not set. Put it in config.env or export it." % name)
    return value


def es(method, path, body=None, ok=(200, 201)):
    """Send one request to Elasticsearch. Returns (status, parsed JSON body).

    body may be a dict (sent as JSON) or a str (sent as NDJSON, for _bulk).
    Any status not listed in `ok` stops the script with the response text.
    """
    url = setting("ES_URL").rstrip("/") + path
    headers = {"Authorization": "ApiKey " + setting("ES_API_KEY")}
    data = None
    if isinstance(body, str):
        data = body.encode("utf-8")
        headers["Content-Type"] = "application/x-ndjson"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            status, text = response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode("utf-8", "replace")
    except urllib.error.URLError as error:
        sys.exit("ERROR: cannot reach %s: %s" % (url, error.reason))
    if status not in ok:
        sys.exit("ERROR: %s %s returned HTTP %s\n%s" % (method, path, status, text[:2000]))
    try:
        return status, json.loads(text) if text else {}
    except ValueError:
        return status, {}
