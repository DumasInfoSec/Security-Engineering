import copy
import json
import random

import pytest

from conftest import PLANTS, TOOL_OUTPUT, leaked
from scrub_proxy.scrubber import BlockedContent, StreamRestorer
from scrub_proxy.store import PH_RE


def cc_request():
    """A Claude-Code-shaped request with plants in every position we scrub."""
    return {
        "model": "claude-sonnet-5-5",
        "max_tokens": 1024,
        "stream": True,
        "system": [{"type": "text", "text": "You are a coding agent."},
                   {"type": "text", "text": f"User email: {PLANTS['email']}",
                    "cache_control": {"type": "ephemeral"}}],
        "tools": [{"name": "Bash", "description": f"Run commands. Owner {PLANTS['name']}.",
                   "input_schema": {"type": "object", "properties": {
                       "command": {"type": "string", "description": "the command"}}}}],
        "messages": [
            {"role": "user", "content": f"Why does login fail for {PLANTS['email']}?"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "Check git log.", "signature": "sig=="},
                {"type": "text", "text": "Let me look."},
                {"type": "tool_use", "id": "toolu_1", "name": "Bash",
                 "input": {"command": f"grep -r '{PLANTS['pw']}' . && echo {PLANTS['quote_secret']}",
                           "env": {"TOKEN": PLANTS["gh"]}}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": TOOL_OUTPUT},
                {"type": "tool_result", "tool_use_id": "toolu_2",
                 "content": [{"type": "text", "text": f"card={PLANTS['card']} ip={PLANTS['ip']}"}]},
                {"type": "text", "text": f"Also {PLANTS['name2']} at {PLANTS['phone']}"}]},
        ],
    }


def test_detects_every_plant_in_tool_output(scrubber):
    out = scrubber.scrub_texts([TOOL_OUTPUT])[0]
    assert leaked(out) == [], out
    assert "3f2a9c1e4b5d6a7f8e9d0c1b2a3f4e5d6c7b8a90" in out  # git SHA kept (hex entropy off)
    assert "def get_user(user_id)" in out  # code kept


def test_request_has_no_leaks(scrubber):
    body, stats = scrubber.scrub_request(cc_request())
    blob = json.dumps(body, ensure_ascii=False)
    assert leaked(blob) == []
    assert leaked(json.dumps(body)) == []
    scrubber.guard(blob.encode())  # final guard agrees
    # passthrough parts untouched
    assert body["messages"][1]["content"][0] == {"type": "thinking", "thinking": "Check git log.",
                                                 "signature": "sig=="}
    assert body["tools"][0]["name"] == "Bash"
    assert body["system"][-1]["text"].startswith("Some values in this conversation")


def test_tool_addition_descriptions_scrubbed(scrubber):
    req = {"messages": [{"role": "user", "content": [{"type": "tool_addition", "tool": {
        "type": "tool_definition", "definition": {"name": "mcp__x", "description":
        f"Ask {PLANTS['email']}", "input_schema": {"type": "object"}}}}]}]}
    body, _ = scrubber.scrub_request(req)
    assert leaked(json.dumps(body)) == []
    assert body["messages"][0]["content"][0]["tool"]["definition"]["name"] == "mcp__x"


def test_cross_block_reveal_with_fresh_store(scrubber, tmp_path):
    """Value only identifiable in a later block must still be scrubbed in earlier blocks."""
    from scrub_proxy.scrubber import Scrubber
    from scrub_proxy.store import Store
    fresh = Scrubber(Store(str(tmp_path)), ner=scrubber.ner, gitleaks=scrubber.gitleaks)
    body, _ = fresh.scrub_request(cc_request())
    blob = json.dumps(body, ensure_ascii=False)
    assert PLANTS["pw"] not in blob
    fresh.guard(blob.encode())


def test_deterministic_for_prompt_cache(scrubber):
    a = json.dumps(scrubber.scrub_request(cc_request())[0])
    b = json.dumps(scrubber.scrub_request(cc_request())[0])
    assert a == b


def test_roundtrip_restore(scrubber):
    req = cc_request()
    scrubbed, _ = scrubber.scrub_request(copy.deepcopy(req))
    tr = scrubbed["messages"][2]["content"][0]["content"]
    assert scrubber.restore_text(tr) == TOOL_OUTPUT
    inp = scrubbed["messages"][1]["content"][2]["input"]
    assert scrubber.restore_obj(inp) == req["messages"][1]["content"][2]["input"]


def test_known_values_rescrubbed_in_new_context(scrubber):
    scrubber.scrub_texts([TOOL_OUTPUT])
    # lowercase prose where NER would not fire; known-value pass must still catch it
    out = scrubber.scrub_texts([f"ok so maria said Maria Kowalczyk's key is {PLANTS['pw']}!"])[0]
    assert "Maria Kowalczyk" not in out and PLANTS["pw"] not in out


def test_guard_trips_on_unscrubbed_value(scrubber):
    from scrub_proxy.scrubber import LeakGuardError
    scrubber.scrub_texts([TOOL_OUTPUT])
    with pytest.raises(LeakGuardError):
        scrubber.guard(json.dumps({"x": PLANTS["gh"]}).encode())


@pytest.mark.parametrize("block", [
    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}},
    {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBE"}},
    {"type": "mystery_block"},
])
def test_unscannable_blocks_fail_closed(scrubber, block):
    req = {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": [block]}]}]}
    with pytest.raises(BlockedContent):
        scrubber.scrub_request(req)


def _stream_through(scrubber, text, json_escape, rng):
    r = StreamRestorer(scrubber, json_escape)
    out, i = [], 0
    while i < len(text):
        n = rng.randint(1, 7)
        out.append(r.feed(text[i:i + n]))
        i += n
    out.append(r.flush())
    return "".join(out)


def test_stream_restore_every_split(scrubber):
    scrubbed = scrubber.scrub_texts([TOOL_OUTPUT])[0]
    assert PH_RE.search(scrubbed)
    rng = random.Random(0)
    for _ in range(200):
        assert _stream_through(scrubber, scrubbed, False, rng) == TOOL_OUTPUT
    # every single split point of a short string with a placeholder
    ph = scrubber.store.by_val[PLANTS["email"]]
    s = f"mail {ph}, done"
    for cut in range(len(s) + 1):
        r = StreamRestorer(scrubber, False)
        assert r.feed(s[:cut]) + r.feed(s[cut:]) + r.flush() == f"mail {PLANTS['email']}, done"


def test_stream_restore_json_escaping(scrubber):
    scrubber.scrub_texts(["x"])  # ensure always-values registered
    ph = scrubber.store.by_val[PLANTS["quote_secret"]]
    ph2 = scrubber.store.by_val[PLANTS["name2"]] if PLANTS["name2"] in scrubber.store.by_val else None
    obj = {"command": f"echo {ph} > /tmp/x", "who": ph2 or "n/a"}
    partial = json.dumps(obj)
    rng = random.Random(1)
    for _ in range(100):
        got = json.loads(_stream_through(scrubber, partial, True, rng))
        assert got["command"] == f"echo {PLANTS['quote_secret']} > /tmp/x"
        if ph2:
            assert got["who"] == PLANTS["name2"]


def test_unknown_placeholder_left_alone(scrubber):
    assert scrubber.restore_text("PII_NAME_deadbeef") == "PII_NAME_deadbeef"
