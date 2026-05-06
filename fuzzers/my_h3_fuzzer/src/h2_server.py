#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import os
import traceback
from datetime import datetime, timezone

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    RequestReceived,
    DataReceived,
    StreamEnded,
    StreamReset,
    ConnectionTerminated,
    RemoteSettingsChanged,
)

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 28081

LOG_DIR = "./"
LOG_FILE = os.path.join(LOG_DIR, "h2_requests.log")

os.makedirs(LOG_DIR, exist_ok=True)


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def safe_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def append_log(text: str) -> None:
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(text)
        f.write("\n" + "=" * 80 + "\n")


class H2CProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.peer = None

        # header_encoding="utf-8" 让 headers 尽量直接返回 str
        self.conn = H2Connection(
            config=H2Configuration(
                client_side=False,
                header_encoding="utf-8",
            )
        )

        # 每个 stream_id 对应一条请求
        self.streams = {}
        # 可选：给每个连接编一个简单 id
        self.conn_id = f"{id(self):x}"

    def connection_made(self, transport):
        self.transport = transport
        self.peer = transport.get_extra_info("peername")
        peer_text = (
            f"{self.peer[0]}:{self.peer[1]}"
            if isinstance(self.peer, tuple) and len(self.peer) >= 2
            else "unknown"
        )

        print(f"[*] New H2 connection from {peer_text}, conn_id={self.conn_id}")

        self.conn.initiate_connection()
        self._flush()

    def data_received(self, data: bytes):
        try:
            events = self.conn.receive_data(data)
        except Exception as e:
            print(f"[!] H2 parse error, conn_id={self.conn_id}: {e}")
            traceback.print_exc()
            if self.transport is not None:
                self.transport.close()
            return

        for event in events:
            try:
                self._handle_event(event)
            except Exception as e:
                print(
                    f"[!] Event handling error, conn_id={self.conn_id}, "
                    f"event={type(event).__name__}: {e}"
                )
                traceback.print_exc()
                if self.transport is not None:
                    self.transport.close()
                return

        self._flush()

    def _handle_event(self, event):
        if isinstance(event, RequestReceived):
            # 初始化 stream 状态
            self.streams.setdefault(
                event.stream_id,
                {
                    "headers": [],
                    "body": bytearray(),
                },
            )

            for k, v in event.headers:
                self.streams[event.stream_id]["headers"].append(
                    (safe_text(k), safe_text(v))
                )

        elif isinstance(event, DataReceived):
            self.streams.setdefault(
                event.stream_id,
                {
                    "headers": [],
                    "body": bytearray(),
                },
            )
            self.streams[event.stream_id]["body"].extend(event.data)

            # HTTP/2 流控窗口确认
            self.conn.acknowledge_received_data(
                event.flow_controlled_length,
                event.stream_id,
            )

        elif isinstance(event, StreamEnded):
            self._finish_stream(event.stream_id)

        elif isinstance(event, StreamReset):
            print(
                f"[!] Stream reset, conn_id={self.conn_id}, "
                f"stream_id={event.stream_id}"
            )
            self.streams.pop(event.stream_id, None)

        elif isinstance(event, ConnectionTerminated):
            print(
                f"[*] Connection terminated, conn_id={self.conn_id}, "
                f"error_code={event.error_code}, last_stream_id={event.last_stream_id}"
            )

        elif isinstance(event, RemoteSettingsChanged):
            # 可按需打印调试
            pass

    def _finish_stream(self, stream_id: int):
        state = self.streams.pop(
            stream_id,
            {
                "headers": [],
                "body": bytearray(),
            },
        )

        headers = state["headers"]
        body = bytes(state["body"])

        method = ""
        path = ""
        scheme = ""
        authority = ""

        pseudo_headers = []
        normal_headers = []

        for k, v in headers:
            k = safe_text(k)
            v = safe_text(v)

            if k == ":method":
                method = v
            elif k == ":path":
                path = v
            elif k == ":scheme":
                scheme = v
            elif k == ":authority":
                authority = v

            if k.startswith(":"):
                pseudo_headers.append(f"{k}: {v}")
            else:
                normal_headers.append(f"{k}: {v}")

        peer_text = (
            f"{self.peer[0]}:{self.peer[1]}"
            if isinstance(self.peer, tuple) and len(self.peer) >= 2
            else "unknown"
        )

        log_text = (
            f"[{now()}] HTTP/2 request\n"
            f"conn_id: {self.conn_id}\n"
            f"client: {peer_text}\n"
            f"stream_id: {stream_id}\n"
            f"method: {method}\n"
            f"path: {path}\n"
            f"scheme: {scheme}\n"
            f"authority: {authority}\n"
            f"pseudo_headers:\n"
            f"{chr(10).join(pseudo_headers) if pseudo_headers else '(none)'}\n"
            f"headers:\n"
            f"{chr(10).join(normal_headers) if normal_headers else '(none)'}\n"
            f"body_length: {len(body)}\n"
            f"body:\n{safe_text(body)}\n"
        )

        append_log(log_text)

        # 返回 200 + 空 body
        response_headers = [
            (":status", "200"),
            ("content-length", "0"),
        ]
        self.conn.send_headers(stream_id, response_headers, end_stream=True)

        print(
            f"[+] Responded 200, conn_id={self.conn_id}, stream_id={stream_id}, "
            f"method={method}, path={path}, body_len={len(body)}"
        )

    def eof_received(self):
        # 明确返回 False，保持默认行为
        return False

    def connection_lost(self, exc):
        if exc:
            print(f"[!] Connection lost with error, conn_id={self.conn_id}: {exc}")
        else:
            print(f"[*] Connection closed, conn_id={self.conn_id}")
        self.streams.clear()

    def _flush(self):
        if self.transport is None:
            return
        data = self.conn.data_to_send()
        if data:
            self.transport.write(data)


async def main():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(H2CProtocol, LISTEN_HOST, LISTEN_PORT)

    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[*] HTTP/2 cleartext server listening on {sockets}")
    print(f"[*] Request log file: {LOG_FILE}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user")