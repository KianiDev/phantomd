
# Prevent DNS bypassing by routing all client connections on 53 port for DNS through the internal resolver


import socket
import asyncio
import configparser
import os


# Read config file
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'phantomd.conf')
config = configparser.ConfigParser()
config.read(CONFIG_PATH)

HIJACK_ENABLED = config.getboolean('hijackd', 'enabled', fallback=False)
RESOLVER_IP = config.get('resolver', 'listen_ip', fallback='127.0.0.1')
RESOLVER_PORT = config.getint('resolver', 'listen_port', fallback=5353)

class UDPProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, resolver_ip, resolver_port):
        self.resolver_ip = resolver_ip
        self.resolver_port = resolver_port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.create_task(self.handle_query(data, addr))

    async def handle_query(self, data, addr):
        loop = asyncio.get_running_loop()
        # Forward to internal resolver
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(data, (self.resolver_ip, self.resolver_port))
            response, _ = sock.recvfrom(4096)
            sock.close()
            self.transport.sendto(response, addr)
        except Exception as e:
            print(f"UDP DNS proxy error: {e}")

async def tcp_proxy_server(listen_ip, listen_port, resolver_ip, resolver_port):
    server = await asyncio.start_server(
        lambda r, w: tcp_proxy_handler(r, w, resolver_ip, resolver_port),
        listen_ip, listen_port
    )
    async with server:
        await server.serve_forever()

async def tcp_proxy_handler(reader, writer, resolver_ip, resolver_port):
    try:
        # Read DNS query length and data
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, 'big')
        data = await reader.readexactly(length)
        # Forward to internal resolver
        r_reader, r_writer = await asyncio.open_connection(resolver_ip, resolver_port)
        r_writer.write(length_bytes + data)
        await r_writer.drain()
        # Read response length and data
        resp_len_bytes = await r_reader.readexactly(2)
        resp_len = int.from_bytes(resp_len_bytes, 'big')
        response = await r_reader.readexactly(resp_len)
        r_writer.close()
        await r_writer.wait_closed()
        # Send response back to client
        writer.write(resp_len_bytes + response)
        await writer.drain()
    except Exception as e:
        print(f"TCP DNS proxy error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    if not HIJACK_ENABLED:
        print("hijackd is disabled in config. Exiting.")
        return
    loop = asyncio.get_running_loop()
    print(f"Starting UDP DNS proxy on 0.0.0.0:{RESOLVER_PORT} -> {RESOLVER_IP}:{RESOLVER_PORT}")
    transport, _ = await loop.create_datagram_endpoint(
        lambda: UDPProxyProtocol(RESOLVER_IP, RESOLVER_PORT),
        local_addr=('0.0.0.0', RESOLVER_PORT)
    )
    print(f"Starting TCP DNS proxy on 0.0.0.0:{RESOLVER_PORT} -> {RESOLVER_IP}:{RESOLVER_PORT}")
    await tcp_proxy_server('0.0.0.0', RESOLVER_PORT, RESOLVER_IP, RESOLVER_PORT)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except PermissionError:
        print("Permission denied: you must run as root to bind to port 53.")

