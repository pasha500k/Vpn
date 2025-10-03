from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import sys
import uuid
from pathlib import Path
from typing import Optional

DEFAULT_BUFFER = 65536


class VpnClient:
    def __init__(
        self,
        host: str,
        port: int,
        mode: str,
        auth: dict,
        ca_file: Optional[Path] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.mode = mode
        self.auth = auth
        self.ca_file = ca_file
        self._ssl_context = self._create_ssl_context()
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self.ca_file:
            context.load_verify_locations(str(self.ca_file))
        context.check_hostname = False
        return context

    async def connect(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(
            host=self.host, port=self.port, ssl=self._ssl_context
        )
        await self._send_json(
            {
                "action": "handshake",
                "protocol": "vmess",
                "mode": self.mode,
                "auth": self.auth,
                "client_id": str(uuid.uuid4()),
            }
        )
        response = await self._read_json()
        if response.get("status") != "ok":
            raise RuntimeError(f"Handshake failed: {response}")
        if response.get("protocol") != "vmess":
            raise RuntimeError("Server does not speak VMess")
        allowed = response.get("domains", [])
        server_id = response.get("server_id", "vmess-gateway")
        quota = response.get("quota_seconds")
        if quota is None:
            quota_msg = "безлимитно"
        else:
            hours, remainder = divmod(int(quota), 3600)
            minutes = remainder // 60
            quota_msg = f"осталось {hours}ч {minutes}м"
        print(
            f"Подключено к {server_id} в режиме {self.mode}. "
            f"Доступ: {quota_msg}. Разрешённые домены: {', '.join(allowed) or 'весь трафик'}",
            file=sys.stderr,
        )

    async def open_tunnel(self, domain: str, port: int, payload: bytes) -> bytes:
        if self.reader is None or self.writer is None:
            raise RuntimeError("Client not connected")
        await self._send_json({"action": "connect", "domain": domain, "port": port})
        response = await self._read_json()
        if response.get("status") != "connected":
            raise RuntimeError(f"Connect failed: {response}")
        await self._send_chunk(payload)
        await self._send_chunk(b"")  # close write side
        chunks: list[bytes] = []
        while True:
            size_data = await self.reader.readexactly(4)
            size = int.from_bytes(size_data, byteorder="big")
            if size == 0:
                break
            chunk = await self.reader.readexactly(size)
            chunks.append(chunk)
        await self._send_json({"action": "close"})
        return b"".join(chunks)

    async def close(self) -> None:
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()

    async def _read_json(self) -> dict:
        if self.reader is None:
            raise RuntimeError("Client not connected")
        line = await self.reader.readline()
        if not line:
            raise RuntimeError("Connection closed by server")
        return json.loads(line.decode())

    async def _send_json(self, payload: dict) -> None:
        if self.writer is None:
            raise RuntimeError("Client not connected")
        data = json.dumps(payload).encode() + b"\n"
        self.writer.write(data)
        await self.writer.drain()

    async def _send_chunk(self, data: bytes) -> None:
        if self.writer is None:
            raise RuntimeError("Client not connected")
        self.writer.write(len(data).to_bytes(4, byteorder="big") + data)
        await self.writer.drain()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Launchpad VPN Client")
    parser.add_argument("--server", required=True, help="Домен или IP VPN-сервера")
    parser.add_argument("--port", type=int, default=9443, help="Порт VPN-сервера")
    parser.add_argument("--mode", choices=["full", "domains"], default="domains", help="Режим работы VPN")
    parser.add_argument("--key", help="Активационный ключ")
    parser.add_argument("--username", help="Логин пользователя")
    parser.add_argument("--password", help="Пароль пользователя")
    parser.add_argument("--domain", required=True, help="Целевой домен")
    parser.add_argument("--target-port", type=int, default=443, help="Порт целевого сервиса")
    parser.add_argument("--payload-file", type=Path, help="Файл с данными запроса")
    parser.add_argument("--ca", type=Path, help="Путь к файлу корневого сертификата")
    args = parser.parse_args()

    if args.key:
        auth = {"type": "key", "value": args.key}
    elif args.username and args.password:
        auth = {"type": "account", "username": args.username, "password": args.password}
    else:
        parser.error("Необходимо указать ключ или пару логин/пароль пользователя")

    if args.payload_file:
        payload = args.payload_file.read_bytes()
    else:
        print("Введите HTTP-запрос и завершите ввод Ctrl+D:")
        payload = sys.stdin.buffer.read()

    client = VpnClient(host=args.server, port=args.port, mode=args.mode, auth=auth, ca_file=args.ca)
    try:
        await client.connect()
        response = await client.open_tunnel(args.domain, args.target_port, payload)
        sys.stdout.buffer.write(response)
        sys.stdout.flush()
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
