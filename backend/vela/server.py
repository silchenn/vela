"""WebSocket push. Bind only to LAN/loopback addresses; clients authenticate with ?token=."""

import asyncio
import hmac
import json
import time
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from websockets.asyncio.server import ServerConnection, broadcast, serve

from .aggregator import Aggregator


def _dumps(msg: dict) -> str:
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":"))


async def run(aggregator: Aggregator, source, host: str, port: int, token: str, on_ready=None) -> None:
    clients: set[ServerConnection] = set()

    def check_token(connection, request):
        given = parse_qs(urlsplit(request.path).query).get("token", [""])[0]
        if not hmac.compare_digest(given.encode(), token.encode()):
            return connection.respond(HTTPStatus.UNAUTHORIZED, "invalid token\n")
        return None

    async def handler(connection: ServerConnection):
        clients.add(connection)
        try:
            for node in aggregator.nodes():
                await connection.send(_dumps(node))
            await connection.wait_closed()
        finally:
            clients.discard(connection)

    loop = asyncio.get_running_loop()
    # The capture callback runs on Scapy's thread; hand events to the event loop so the aggregator is only touched from one thread
    source.start(lambda ev: loop.call_soon_threadsafe(aggregator.add, ev))
    try:
        async with serve(handler, host, port, process_request=check_token):
            if on_ready:
                on_ready()
            interval = aggregator.window_ms / 1000
            next_tick = loop.time() + interval
            while True:
                await asyncio.sleep(max(0.0, next_tick - loop.time()))
                next_tick += interval
                msgs = aggregator.flush(int(time.time() * 1000))
                if clients:
                    for msg in msgs:
                        broadcast(clients, _dumps(msg))
    finally:
        source.stop()
