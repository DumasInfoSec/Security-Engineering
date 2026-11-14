"""End-to-end: client -> proxy -> mock upstream. The mock records exactly what it received."""
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from conftest import PLANTS, leaked
from scrub_proxy.server import Proxy
from scrub_proxy.store import PH_RE
from test_scrub import cc_request


def sse(name, data):
    return f"event: {name}\ndata: {json.dumps(data)}\n\n"


def make_upstream(received):
    async def messages(req):
        raw = await req.read()
        received.append({"path": req.path, "body": raw.decode(), "headers": dict(req.headers)})
        body = json.loads(raw)
        # echo back placeholders the proxy sent, as the model would
        phs = sorted(set(PH_RE.findall(raw.decode())))
        text = "Found: " + ", ".join(phs)
        tool_input = json.dumps({"command": "echo " + " ".join(phs)})
        if not body.get("stream"):
            return web.json_response({
                "id": "msg_1", "type": "message", "role": "assistant", "model": body["model"],
                "content": [{"type": "text", "text": text},
                            {"type": "tool_use", "id": "toolu_9", "name": "Bash",
                             "input": json.loads(tool_input)}],
                "stop_reason": "tool_use", "usage": {"input_tokens": 1, "output_tokens": 1}})
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(req)
        await resp.write(sse("message_start", {"type": "message_start", "message": {
            "id": "msg_1", "type": "message", "role": "assistant", "content": []}}).encode())
        await resp.write(sse("content_block_start", {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "text", "text": ""}}).encode())
        # 3-char deltas split placeholders everywhere; also split SSE frames mid-event
        frames = "".join(sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                         "delta": {"type": "text_delta", "text": text[i:i + 3]}})
                         for i in range(0, len(text), 3))
        frames += sse("content_block_stop", {"type": "content_block_stop", "index": 0})
        frames += sse("content_block_start", {"type": "content_block_start", "index": 1,
                      "content_block": {"type": "tool_use", "id": "toolu_9", "name": "Bash", "input": {}}})
        frames += "".join(sse("content_block_delta", {"type": "content_block_delta", "index": 1,
                          "delta": {"type": "input_json_delta", "partial_json": tool_input[i:i + 5]}})
                          for i in range(0, len(tool_input), 5))
        frames += sse("content_block_stop", {"type": "content_block_stop", "index": 1})
        frames += sse("message_stop", {"type": "message_stop"})
        b = frames.encode()
        for i in range(0, len(b), 37):
            await resp.write(b[i:i + 37])
        await resp.write_eof()
        return resp

    async def count(req):
        received.append({"path": req.path, "body": (await req.read()).decode()})
        return web.json_response({"input_tokens": 42})

    app = web.Application()
    app.router.add_post("/v1/messages", messages)
    app.router.add_post("/v1/messages/count_tokens", count)
    return app


@pytest.fixture
async def env(scrubber):
    received = []
    up = TestServer(make_upstream(received))
    await up.start_server()
    proxy = Proxy(scrubber, str(up.make_url("")))
    client = TestClient(TestServer(proxy.app()))
    await client.start_server()
    yield client, received
    await client.close()
    await up.close()


def parse_sse(raw: str):
    text, tool, events = "", "", []
    for ev in raw.strip().split("\n\n"):
        data = next(l[6:] for l in ev.split("\n") if l.startswith("data: "))
        d = json.loads(data)
        events.append(d)
        if d["type"] == "content_block_delta":
            text += d["delta"].get("text", "")
            tool += d["delta"].get("partial_json", "")
    return text, tool, events


async def test_streaming_end_to_end(env):
    client, received = env
    r = await client.post("/v1/messages?beta=true", json=cc_request(),
                          headers={"Authorization": "Bearer oauth-token-xyz",
                                   "anthropic-beta": "oauth-2025-04-20"})
    assert r.status == 200
    raw = await r.text()
    assert len(received) == 1
    sent = received[0]
    assert leaked(sent["body"]) == []
    assert sent["headers"]["Authorization"] == "Bearer oauth-token-xyz"  # auth forwarded
    text, tool, events = parse_sse(raw)
    assert not PH_RE.search(text), text
    for k in ("email", "name", "gh", "pw", "card"):
        assert PLANTS[k] in text, (k, text)
    cmd = json.loads(tool)["command"]
    assert PLANTS["quote_secret"] in cmd and PLANTS["email"] in cmd
    assert events[-1]["type"] == "message_stop"


async def test_non_streaming_end_to_end(env):
    client, received = env
    req = cc_request()
    req["stream"] = False
    r = await client.post("/v1/messages", json=req)
    body = await r.json()
    assert leaked(received[0]["body"]) == []
    assert PLANTS["email"] in body["content"][0]["text"]
    assert PLANTS["quote_secret"] in body["content"][1]["input"]["command"]


async def test_count_tokens_scrubbed(env):
    client, received = env
    r = await client.post("/v1/messages/count_tokens", json=cc_request())
    assert (await r.json()) == {"input_tokens": 42}
    assert leaked(received[0]["body"]) == []


async def test_fail_closed_on_scanner_error(env, scrubber, monkeypatch):
    client, received = env
    def boom(*a, **k):
        raise RuntimeError("detector crashed")
    monkeypatch.setattr(scrubber, "detect", boom)
    r = await client.post("/v1/messages", json=cc_request())
    assert r.status == 502
    assert received == []


async def test_image_blocked_not_forwarded(env):
    client, received = env
    req = {"model": "m", "max_tokens": 1, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "x"}}]}]}
    r = await client.post("/v1/messages", json=req)
    assert r.status == 400 and received == []


async def test_unknown_post_path_refused(env):
    client, received = env
    r = await client.post("/v1/files", data=PLANTS["gh"])
    assert r.status == 403 and received == []


async def test_image_end_to_end(env, scrubber):
    from test_images import IMG_PLANTS, LINES, block, leaked_in_ocr, ocr_text, render
    client, received = env
    req = cc_request()
    req["stream"] = False
    req["messages"].append({"role": "user", "content": [block(render(LINES)),
                            {"type": "text", "text": "what's in this screenshot?"}]})
    r = await client.post("/v1/messages", json=req)
    assert r.status == 200
    sent = json.loads(received[0]["body"])
    img = sent["messages"][-1]["content"][0]
    assert leaked_in_ocr(ocr_text(scrubber, img), IMG_PLANTS) == []
