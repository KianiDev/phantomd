# tests/test_mitm_socket.py
import asyncio
import pytest
import tempfile
import os
from unittest.mock import AsyncMock, patch

from core.dserver import run_server, DoHSocketHandler
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
        # Mock the forward_dns_query to return a fixed response
        resolver.forward_dns_query = AsyncMock(return_value=b"\x00\x01\x02\x03")

        # Start the socket server in a background task
        server_task = None
        try:
            server = await asyncio.start_unix_server(
                lambda: DoHSocketHandler(resolver),
                socket_path
            )
            server_task = asyncio.create_task(server.serve_forever())

            # Connect a client
            reader, writer = await asyncio.open_unix_connection(socket_path)

            # Send a query: 2-byte length + dummy data
            query = b"\x00\x04test"
            writer.write(query)
            await writer.drain()

            # Read response: 2-byte length + data
            len_data = await reader.readexactly(2)
            resp_len = int.from_bytes(len_data, "big")
            response = await reader.readexactly(resp_len)

            assert response == b"\x00\x01\x02\x03"
            writer.close()
            await writer.wait_closed()
        finally:
            if server_task:
                server_task.cancel()
                await server_task