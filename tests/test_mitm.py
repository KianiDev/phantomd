# tests/test_mitm.py
import asyncio
import pytest
import tempfile
import os
from unittest.mock import AsyncMock

from core.dserver import DoHSocketHandler
from core.resolver import DNSResolver


@pytest.mark.asyncio
async def test_mitm_socket_handler():
    """Test that the Unix socket handler correctly forwards DNS queries and returns responses."""
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "doh.sock")
        resolver = DNSResolver(
            upstream_dns="1.1.1.1",
            protocol="udp",
            disable_ipv6=True,
        )
        resolver.forward_dns_query = AsyncMock(return_value=b"\x00\x01\x02\x03")

        # Explicitly use protocol_factory argument
        server = await asyncio.start_unix_server(
            protocol_factory=lambda: DoHSocketHandler(resolver),
            path=socket_path
        )
        server_task = asyncio.create_task(server.serve_forever())

        try:
            # Wait for socket to become available
            await asyncio.sleep(0.1)

            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(socket_path), timeout=5.0
            )

            query = b"\x00\x04test"
            writer.write(query)
            await writer.drain()

            len_data = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
            resp_len = int.from_bytes(len_data, "big")
            response = await asyncio.wait_for(reader.readexactly(resp_len), timeout=5.0)

            assert response == b"\x00\x01\x02\x03"

            writer.close()
            await writer.wait_closed()
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass