import os

import pytest

from scrub_proxy.detectors import NER, Gitleaks
from scrub_proxy.scrubber import Scrubber
from scrub_proxy.store import Store

# Planted values. Every one must be absent from anything sent upstream.
PLANTS = {
    "name": "Maria Kowalczyk",
    "name2": "José Núñez-García",
    "email": "maria.k@acme-corp.io",
    "ssn": "123-45-6789",
    "card": "4111 1111 1111 1111",
    "phone": "(415) 555-0132",
    "ip": "10.20.30.40",
    "address": "742 Evergreen Terrace, Springfield IL 62704",
    "gh": "ghp" + "_8f3kL0pQz9XyWv2bN4mR7tS1" + "uA6cD5eF0gH1",
    "aws": "AKIA" + "IOSFODNN7EXAMPLQ",
    "pw": "hunter2xyz",
    "urlpw": "S3cr3tPassw0rd",
    "anthropic": "sk-ant" + "-api03-Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0LzXcVbNm",
    "quote_secret": 'p@ss"word\\with\\escapes',
    "jwt": ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"]),
}
PEM = ("-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq9w8XoZ3fKq1Lr0u5tq2P4yQ\n"
       "p9sVh3Zl5Jm2kR8wE1tY6uI0oP3aS7dF4gH2jK9l\n-----END RSA " + "PRIVATE KEY-----")
PLANTS["pem_body"] = "MIIEowIBAAKCAQEA7bq9w8XoZ3fKq1Lr0u5tq2P4yQ"

TOOL_OUTPUT = f"""$ git log -1
commit 3f2a9c1e4b5d6a7f8e9d0c1b2a3f4e5d6c7b8a90
Author: {PLANTS['name']} <{PLANTS['email']}>
    Fix billing for customer (SSN {PLANTS['ssn']}), card {PLANTS['card']}
$ cat .env
DATABASE_URL=postgres://admin:{PLANTS['urlpw']}@db.internal:5432/prod
GITHUB_TOKEN={PLANTS['gh']}
AWS_ACCESS_KEY_ID={PLANTS['aws']}
ANTHROPIC_API_KEY={PLANTS['anthropic']}
AUTH={PLANTS['jwt']}
password = "{PLANTS['pw']}"
{PEM}
Ship to {PLANTS['address']}, call {PLANTS['phone']}. Server {PLANTS['ip']}.
Reviewer: {PLANTS['name2']} signed off.
def get_user(user_id): return db.query(User).filter(User.id == user_id).first()
"""


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory):
    return str(tmp_path_factory.mktemp("scrubdata"))


@pytest.fixture(scope="session")
def store(data_dir):
    return Store(data_dir)


@pytest.fixture(scope="session")
def scrubber(store):
    ner = NER(os.environ.get("SCRUB_NER_MODEL", "knowledgator/gliner-pii-base-v1.0"), store)
    # quote_secret has no detectable shape; it exercises the always-list and JSON escaping
    from scrub_proxy.images import ImageScrubber
    return Scrubber(store, ner=ner, gitleaks=Gitleaks(), images=ImageScrubber(store),
                    always={PLANTS["quote_secret"]: "PASSWORD"})


def leaked(blob: str) -> list[str]:
    """Return plant keys whose value appears in blob raw or JSON-escaped."""
    import json
    out = []
    for k, v in PLANTS.items():
        forms = {v, json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1]}
        if any(f in blob for f in forms):
            out.append(k)
    return out
