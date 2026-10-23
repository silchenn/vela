"""调试客户端：python -m vela.watch 'ws://HOST:PORT/?token=...'，逐行打印收到的消息。"""

import asyncio
import sys

from websockets.asyncio.client import connect


async def watch(url: str) -> None:
    async with connect(url) as ws:
        async for msg in ws:
            print(msg, flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("用法：python -m vela.watch 'ws://HOST:PORT/?token=...'")
    try:
        asyncio.run(watch(sys.argv[1]))
    except KeyboardInterrupt:
        pass
