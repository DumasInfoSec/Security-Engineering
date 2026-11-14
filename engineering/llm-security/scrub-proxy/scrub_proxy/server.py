"""aiohttp reverse proxy for the Anthropic Messages API with scrub/restore."""
import asyncio
import json
import logging
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

import aiohttp
from aiohttp import web

from .scrubber import BlockedContent, Scrubber, StreamRestorer

log = logging.getLogger("scrub-proxy")

HOP = {"host", "content-length", "transfer-encoding", "connection", "keep-alive",
       "accept-encoding", "proxy-authorization", "proxy-connection", "te", "upgrade",
       "content-encoding"}
SCRUB_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}


def _err(status: int, etype: str, msg: str) -> web.Response:
    return web.json_response(
        {"type": "error", "error": {"type": etype, "message": f"scrub-proxy: {msg}"}},
        status=status)


def _fwd_headers(h) -> dict:
    out = {k: v for k, v in h.items() if k.lower() not in HOP}
    out["Accept-Encoding"] = "identity"
    return out


def _resp_headers(h) -> dict:
    return {k: v for k, v in h.items() if k.lower() not in HOP}


def _sse_event(name: str, data: dict) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()


class SSETransformer:
    def __init__(self, scrubber: Scrubber):
        self.s = scrubber
        self.restorers: dict[int, tuple[StreamRestorer, str, str]] = {}

    def event(self, raw: bytes) -> list[bytes]:
        name, data_lines = None, []
        for line in raw.decode("utf-8").split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
        if not data_lines:
            return [raw + b"\n\n"]
        try:
            d = json.loads("\n".join(data_lines))
        except ValueError:
            return [raw + b"\n\n"]
        name = name or d.get("type")
        t = d.get("type")
        if t == "content_block_start":
            cb = d.get("content_block", {})
            if cb.get("type") == "text":
                cb["text"] = self.s.restore_text(cb.get("text", ""))
                self.restorers[d["index"]] = (StreamRestorer(self.s, False), "text_delta", "text")
            elif cb.get("type") == "tool_use":
                cb["input"] = self.s.restore_obj(cb.get("input", {}))
                self.restorers[d["index"]] = (
                    StreamRestorer(self.s, True), "input_json_delta", "partial_json")
            return [_sse_event(name, d)]
        if t == "content_block_delta":
            r = self.restorers.get(d.get("index"))
            delta = d.get("delta", {})
            if r and delta.get("type") == r[1]:
                out = r[0].feed(delta.get(r[2], ""))
                if not out:
                    return []
                delta[r[2]] = out
            return [_sse_event(name, d)]
        if t == "content_block_stop":
            out = []
            r = self.restorers.pop(d.get("index"), None)
            if r:
                rest = r[0].flush()
                if rest:
                    out.append(_sse_event("content_block_delta", {
                        "type": "content_block_delta", "index": d["index"],
                        "delta": {"type": r[1], r[2]: rest}}))
            return out + [_sse_event(name, d)]
        return [_sse_event(name, d)]


class Proxy:
    def __init__(self, scrubber: Scrubber, upstream: str, passthrough_post: set | None = None):
        self.s = scrubber
        self.upstream = upstream.rstrip("/")
        self.passthrough_post = passthrough_post or set()
        self.pool = ThreadPoolExecutor(max_workers=1)  # NER/gitleaks are CPU-bound; serialize
        self.session: aiohttp.ClientSession | None = None

    async def _on_startup(self, app):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_read=600))

    async def _on_cleanup(self, app):
        await self.session.close()

    def app(self) -> web.Application:
        app = web.Application(client_max_size=64 * 1024 * 1024)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        return app

    async def handle(self, req: web.Request) -> web.StreamResponse:
        if req.path in SCRUB_PATHS and req.method == "POST":
            return await self.messages(req)
        if req.method in ("GET", "HEAD", "OPTIONS") or req.path in self.passthrough_post:
            return await self.passthrough(req)
        log.warning("refused %s %s (not a scrubbed endpoint)", req.method, req.path)
        return _err(403, "permission_error", f"{req.method} {req.path} not allowed (fail-closed)")

    async def passthrough(self, req):
        body = await req.read()
        async with self.session.request(req.method, self.upstream + req.path_qs, data=body or None,
                                        headers=_fwd_headers(req.headers)) as up:
            data = await up.read()
            return web.Response(status=up.status, body=data, headers=_resp_headers(up.headers))

    async def messages(self, req: web.Request) -> web.StreamResponse:
        t0 = time.monotonic()
        try:
            body = json.loads(await req.read())
            loop = asyncio.get_running_loop()
            body, stats = await loop.run_in_executor(
                self.pool, self.s.scrub_request, body, os.environ.get("SCRUB_NOTE", "1") != "0")
            data = json.dumps(body, ensure_ascii=False).encode()
            self.s.guard(data)
        except BlockedContent as e:
            log.warning("blocked: %s", e)
            return _err(400, "invalid_request_error", str(e))
        except Exception as e:  # fail closed: nothing is forwarded
            log.error("scrub failed: %s\n%s", e, traceback.format_exc())
            return _err(502, "api_error", f"scrub failed, request not forwarded ({type(e).__name__})")
        log.info("%s scrubbed in %.2fs: %s", req.path, time.monotonic() - t0, dict(stats) or "clean")
        dump = os.environ.get("SCRUB_DUMP_DIR")  # audit: exactly what goes upstream
        if dump:
            os.makedirs(dump, mode=0o700, exist_ok=True)
            with open(os.path.join(dump, f"{time.time():.3f}{req.path.replace('/', '_')}.json"), "wb") as f:
                f.write(data)

        up = await self.session.post(self.upstream + req.path_qs, data=data,
                                     headers=_fwd_headers(req.headers))
        try:
            ctype = up.headers.get("Content-Type", "")
            if "text/event-stream" in ctype:
                return await self._stream(req, up)
            raw = await up.read()
            if "application/json" in ctype and req.path == "/v1/messages" and up.status == 200:
                try:
                    raw = json.dumps(self.s.restore_message(json.loads(raw)), ensure_ascii=False).encode()
                except Exception:
                    log.error("restore failed; returning placeholders\n%s", traceback.format_exc())
            return web.Response(status=up.status, body=raw, headers=_resp_headers(up.headers))
        finally:
            up.release()

    async def _stream(self, req, up) -> web.StreamResponse:
        resp = web.StreamResponse(status=up.status, headers=_resp_headers(up.headers))
        await resp.prepare(req)
        tr, buf = SSETransformer(self.s), b""
        async for chunk in up.content.iter_any():
            buf = (buf + chunk).replace(b"\r\n", b"\n")
            while b"\n\n" in buf:
                ev, buf = buf.split(b"\n\n", 1)
                try:
                    outs = tr.event(ev)
                except Exception:
                    log.error("SSE restore failed; passing event raw\n%s", traceback.format_exc())
                    outs = [ev + b"\n\n"]
                for o in outs:
                    await resp.write(o)
        if buf.strip():
            await resp.write(buf)
        await resp.write_eof()
        return resp
