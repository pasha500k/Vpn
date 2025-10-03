from __future__ import annotations

import asyncio
import json
import logging
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from shared.database import Base, engine
from shared.services import (
    MODE_DOMAINS,
    MODE_FULL,
    SessionInfo,
    allowed_domains,
    begin_session_with_key,
    begin_session_with_user,
    end_session,
    ensure_seed_domains,
)

LOGGER = logging.getLogger("vpn_server")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


@dataclass
class ServerConfig:
    host: str
    port: int
    certificate: Path
    private_key: Path
    max_client_buffer: int = 65536

    @classmethod
    def load(cls, path: Path) -> "ServerConfig":
        data = yaml.safe_load(path.read_text())
        return cls(
            host=data.get("host", "0.0.0.0"),
            port=int(data.get("port", 9443)),
            certificate=Path(data["certificate"]),
            private_key=Path(data["private_key"]),
            max_client_buffer=int(data.get("max_client_buffer", 65536)),
        )


class VpnProxyServer:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.config.certificate, self.config.private_key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    async def start(self) -> None:
        Base.metadata.create_all(bind=engine)
        domains_file = Path("config/domains.yml")
        if domains_file.exists():
            seed_data = yaml.safe_load(domains_file.read_text()) or {}
            ensure_seed_domains(seed_data.get("allowed_domains", []))
        server = await asyncio.start_server(
            client_connected_cb=self.handle_client,
            host=self.config.host,
            port=self.config.port,
            ssl=self._ssl_context,
        )
        addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        LOGGER.info("Server listening on %s", addresses)
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        LOGGER.info("Incoming connection from %s", peername)
        session_info: Optional[SessionInfo] = None
        try:
            handshake = await self._read_json(reader)
            if handshake.get("action") != "handshake":
                raise ValueError("Invalid handshake")
            if handshake.get("protocol") != "vmess":
                await self._send_json(writer, {"status": "error", "reason": "protocol_mismatch"})
                raise ValueError("Unsupported protocol")
            requested_mode = (handshake.get("mode") or MODE_DOMAINS).lower()
            if requested_mode not in {MODE_DOMAINS, MODE_FULL}:
                await self._send_json(writer, {"status": "error", "reason": "invalid_mode"})
                raise ValueError("Invalid mode")

            auth = handshake.get("auth") or {}
            auth_type = auth.get("type")
            if auth_type == "key":
                key_value = auth.get("value")
                if not key_value:
                    await self._send_json(writer, {"status": "error", "reason": "missing_key"})
                    raise ValueError("Missing key")
                session_info = begin_session_with_key(key_value, requested_mode)
                if session_info is None:
                    await self._send_json(writer, {"status": "error", "reason": "invalid_key"})
                    raise ValueError("Invalid key")
            elif auth_type == "account":
                username = auth.get("username")
                password = auth.get("password")
                if not username or not password:
                    await self._send_json(writer, {"status": "error", "reason": "missing_credentials"})
                    raise ValueError("Missing credentials")
                session_info = begin_session_with_user(username, password, requested_mode)
                if session_info is None:
                    await self._send_json(writer, {"status": "error", "reason": "invalid_credentials"})
                    raise ValueError("Invalid credentials")
                if session_info.session_id <= 0 or session_info.quota_seconds == 0:
                    await self._send_json(writer, {"status": "error", "reason": "quota_exhausted"})
                    raise ValueError("Quota exhausted")
            else:
                await self._send_json(writer, {"status": "error", "reason": "missing_auth"})
                raise ValueError("Missing auth block")

            await self._send_json(
                writer,
                {
                    "status": "ok",
                    "protocol": "vmess",
                    "server_id": str(self.config.certificate.stem),
                    "mode": requested_mode,
                    "domains": allowed_domains() if requested_mode == MODE_DOMAINS else [],
                    "quota_seconds": session_info.quota_seconds if session_info else None,
                },
            )
            await self._process_commands(reader, writer, session_info)
        except Exception as exc:  # noqa: BLE001
            LOGGER.error("Error handling client %s: %s", peername, exc)
        finally:
            if session_info:
                end_session(session_info)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            LOGGER.info("Connection closed for %s", peername)

    async def _process_commands(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_info: SessionInfo
    ) -> None:
        while True:
            command = await self._read_json(reader)
            if command is None:
                break
            action = command.get("action")
            if action == "connect":
                domain = command.get("domain")
                port = int(command.get("port", 0))
                if not self._is_domain_allowed(domain, session_info.mode):
                    await self._send_json(writer, {"status": "error", "reason": "domain_not_allowed"})
                    continue
                if port <= 0 or port > 65535:
                    await self._send_json(writer, {"status": "error", "reason": "invalid_port"})
                    continue
                LOGGER.info(
                    "Opening tunnel for %s:%s (session=%s, mode=%s)",
                    domain,
                    port,
                    session_info.session_id,
                    session_info.mode,
                )
                try:
                    target_reader, target_writer = await asyncio.open_connection(domain, port)
                except Exception as exc:  # noqa: BLE001
                    LOGGER.error("Failed to connect to %s:%s - %s", domain, port, exc)
                    await self._send_json(writer, {"status": "error", "reason": "connect_failed"})
                    continue
                await self._send_json(writer, {"status": "connected"})
                await self._pipe(reader, writer, target_reader, target_writer, session_info)
            elif action == "close":
                await self._send_json(writer, {"status": "bye"})
                break
            else:
                await self._send_json(writer, {"status": "error", "reason": "unknown_action"})

    async def _pipe(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
        session_info: SessionInfo,
    ) -> None:
        stop_event = asyncio.Event()

        async def forward(source: asyncio.StreamReader, destination: asyncio.StreamWriter, label: str) -> None:
            try:
                while True:
                    if stop_event.is_set():
                        break
                    length_bytes = await source.readexactly(4)
                    chunk_length = int.from_bytes(length_bytes, byteorder="big")
                    if chunk_length == 0:
                        break
                    data = await source.readexactly(chunk_length)
                    destination.write(data)
                    await destination.drain()
            except asyncio.IncompleteReadError:
                LOGGER.debug("Stream %s closed", label)
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("Forwarding error (%s): %s", label, exc)
            finally:
                stop_event.set()
                try:
                    destination.close()
                    await destination.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

        async def pump_back():
            try:
                while True:
                    if stop_event.is_set():
                        break
                    data = await target_reader.read(self.config.max_client_buffer)
                    if not data:
                        await self._send_chunk(client_writer, b"")
                        stop_event.set()
                        break
                    await self._send_chunk(client_writer, data)
            except Exception as exc:  # noqa: BLE001
                LOGGER.error("Reverse pump error: %s", exc)
                await self._send_chunk(client_writer, b"")
            finally:
                stop_event.set()

        async def enforce_quota() -> None:
            if session_info.quota_seconds is None:
                return
            await asyncio.sleep(session_info.quota_seconds)
            LOGGER.info(
                "Quota reached for session %s (%s seconds)", session_info.session_id, session_info.quota_seconds
            )
            stop_event.set()
            try:
                await self._send_chunk(client_writer, b"")
            except Exception:  # noqa: BLE001
                pass

        tasks = [
            asyncio.create_task(forward(client_reader, target_writer, "client->target")),
            asyncio.create_task(pump_back()),
        ]
        if session_info.quota_seconds:
            tasks.append(asyncio.create_task(enforce_quota()))

        try:
            await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            try:
                target_writer.close()
                await target_writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _read_json(self, reader: asyncio.StreamReader) -> Optional[dict]:
        line = await reader.readline()
        if not line:
            return None
        return json.loads(line.decode())

    async def _send_json(self, writer: asyncio.StreamWriter, payload: dict) -> None:
        data = json.dumps(payload).encode() + b"\n"
        writer.write(data)
        await writer.drain()

    async def _send_chunk(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        size = len(data)
        writer.write(size.to_bytes(4, byteorder="big") + data)
        await writer.drain()

    def _is_domain_allowed(self, domain: Optional[str], mode: str) -> bool:
        if not domain:
            return False
        if mode == MODE_FULL:
            return True
        allowed = allowed_domains()
        return domain in allowed


async def main() -> None:
    config_path = Path("config/server.yml")
    if not config_path.exists():
        raise FileNotFoundError("config/server.yml not found")
    config = ServerConfig.load(config_path)
    server = VpnProxyServer(config)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
