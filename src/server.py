#!/usr/bin/env python3
"""
server.py

A minimal peer "server" process for the class project.

Behavior:
- Creates/uses a directory named `peer_[peerID]` in the current working dir.
- Sets up logging to `log_peer_[peerID].log`.
- Listens on a TCP port and accepts incoming connections.
- For each incoming connection:
    - Receives a 32-byte handshake (header + 10 zero bytes + 4-byte peer ID).
    - Sends back its own 32-byte handshake.
    - Sends a single human-readable hello line:
         "Hello from peer_[serverPeerID]!\n"
    - Logs the connection event (connected-from) with timestamp.
- This is intentionally simple so you can add the full message types later.

Usage:
    python server.py --id 1001 --port 6008
"""

import socket
import threading
import argparse
import logging
import os
from pathlib import Path
import time
import struct

# ----- Constants derived from the project specification -----
HANDSHAKE_HEADER = b'P2PFILESHARINGPROJ'  # 18 bytes
HANDSHAKE_ZERO_BITS = 10                  # 10 zero bytes
HANDSHAKE_LEN = 18 + 10 + 4               # 32 total bytes

# ----- Utility functions -----
def recv_all(sock: socket.socket, n: int) -> bytes | None:
    """
    Receive exactly n bytes from the socket.
    Returns bytes or None if connection closed before n bytes were read.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def make_handshake(peer_id: int) -> bytes:
    """
    Construct the expected 32-byte handshake:
      <18-byte ASCII header> + <10 zero bytes> + <4-byte big-endian peer ID>
    """
    if len(HANDSHAKE_HEADER) != 18:
        raise ValueError("HANDSHAKE_HEADER must be exactly 18 bytes")
    return HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + struct.pack('>I', peer_id)

def parse_handshake(data: bytes) -> int:
    """
    Validate handshake bytes and return the peer ID (int).
    Raises ValueError if header is wrong or size incorrect.
    """
    if data is None or len(data) != HANDSHAKE_LEN:
        raise ValueError("Invalid handshake length")
    header = data[:18]
    if header != HANDSHAKE_HEADER:
        raise ValueError("Invalid handshake header")
    # last 4 bytes are big-endian peer id
    peer_id = struct.unpack('>I', data[-4:])[0]
    return peer_id

# ----- Server class -----
class PeerServer:
    def __init__(self, peer_id: int, host: str, port: int):
        self.peer_id = int(peer_id)
        self.host = host
        self.port = int(port)

        # ensure peer directory exists (per spec: peer_[peerID])
        self.peer_dir = Path(f"peer_{self.peer_id}")
        self.peer_dir.mkdir(parents=True, exist_ok=True)

        # setup logging to file log_peer_[peerID].log and console
        self.logger = logging.getLogger(f"peer{self.peer_id}")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s: %(message)s')

        # file handler
        log_file = Path(f"log_peer_{self.peer_id}.log")
        fh = logging.FileHandler(log_file, mode='a')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # console handler (so you can see output while running)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # tcp socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # allow quick reuse of address in development
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

    def start(self):
        """Bind and accept connections. Spawns a thread per connection."""
        self.sock.bind((self.host, self.port))
        self.sock.listen(8)
        self.running = True
        self.logger.info(f"Peer {self.peer_id} listening on {self.host}:{self.port}")
        try:
            while self.running:
                conn, addr = self.sock.accept()
                # handle connection in new thread
                t = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            self.logger.info("Server interrupted by KeyboardInterrupt, shutting down.")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

    def handle_connection(self, conn: socket.socket, addr):
        """
        Per-connection handler:
        - Read handshake from client (32 bytes)
        - Validate and extract client peer id
        - Write log "Peer [serverID] is connected from Peer [clientID]."
        - Send our handshake back
        - Send simple hello text (newline-terminated)
        - Close connection
        """
        with conn:
            try:
                # 1) receive client's handshake
                data = recv_all(conn, HANDSHAKE_LEN)
                if data is None:
                    self.logger.info(f"Connection from {addr} closed before handshake")
                    return
                try:
                    client_peer_id = parse_handshake(data)
                except ValueError as e:
                    self.logger.info(f"Invalid handshake from {addr}: {e}")
                    return

                # 2) log the incoming connection (server's perspective)
                self.logger.info(f"Peer {self.peer_id} is connected from Peer {client_peer_id}.")

                # 3) send our handshake back
                conn.sendall(make_handshake(self.peer_id))

                # 4) application-level hello message (simple for phase 1)
                hello = f"Hello from peer_{self.peer_id}!\n"
                conn.sendall(hello.encode('utf-8'))

                # done
            except Exception as e:
                # log unexpected exceptions
                self.logger.exception(f"Error handling connection from {addr}: {e}")

# ----- CLI -----
def main():
    parser = argparse.ArgumentParser(description="Simple peer 'server' implementing handshake + hello")
    parser.add_argument("--id", type=int, required=True, help="This peer's ID (integer)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default 0.0.0.0)")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    args = parser.parse_args()

    server = PeerServer(peer_id=args.id, host=args.host, port=args.port)
    server.start()

if __name__ == "__main__":
    main()
