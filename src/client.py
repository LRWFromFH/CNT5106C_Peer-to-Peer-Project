#!/usr/bin/env python3
"""
client.py

A minimal peer "client" that connects to a peer server and performs the
32-byte handshake as specified, then reads a single hello line.

Behavior:
- Creates/uses a directory named `peer_[peerID]` in the current working dir (per spec).
- Sets up logging to `log_peer_[peerID].log`.
- Connects to a remote peer at given host:port.
- Sends its handshake (32 bytes).
- Receives remote handshake (32 bytes) and parses the remote peer ID.
- Logs "Peer [myID] makes a connection to Peer [remoteID]."
- Receives a single text hello line and prints it.

Usage:
    python client.py --id 1002 --host 127.0.0.1 --port 6008
"""

import socket
import argparse
import logging
from pathlib import Path
import struct

HANDSHAKE_HEADER = b'P2PFILESHARINGPROJ'
HANDSHAKE_ZERO_BITS = 10
HANDSHAKE_LEN = 18 + 10 + 4

def recv_all(sock: socket.socket, n: int) -> bytes | None:
    """Receive exactly n bytes from the socket, or None if connection closed early."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def make_handshake(peer_id: int) -> bytes:
    return HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + struct.pack('>I', peer_id)

def parse_handshake(data: bytes) -> int:
    if data is None or len(data) != HANDSHAKE_LEN:
        raise ValueError("Invalid handshake length")
    header = data[:18]
    if header != HANDSHAKE_HEADER:
        raise ValueError("Invalid handshake header")
    peer_id = struct.unpack('>I', data[-4:])[0]
    return peer_id

class PeerClient:
    def __init__(self, peer_id: int):
        self.peer_id = int(peer_id)
        # peer directory as required by the spec (even if we don't use files yet)
        self.peer_dir = Path(f"peer_{self.peer_id}")
        self.peer_dir.mkdir(parents=True, exist_ok=True)

        # logging
        self.logger = logging.getLogger(f"peer{self.peer_id}")
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s: %(message)s')

        # file handler
        log_file = Path(f"log_peer_{self.peer_id}.log")
        fh = logging.FileHandler(log_file, mode='a')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        # console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def connect_and_receive_hello(self, remote_host: str, remote_port: int):
        """
        Connects to remote peer, perform handshake, log connection,
        and print the hello line.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((remote_host, int(remote_port)))

            # send our handshake
            s.sendall(make_handshake(self.peer_id))

            # receive remote handshake
            data = recv_all(s, HANDSHAKE_LEN)
            if data is None:
                raise ConnectionError("Connection closed before handshake response")
            remote_peer_id = parse_handshake(data)

            # log the outgoing connection event
            self.logger.info(f"Peer {self.peer_id} makes a connection to Peer {remote_peer_id}.")

            # receive the hello line (read until newline)
            hello_bytes = bytearray()
            while True:
                ch = s.recv(1)
                if not ch:
                    break
                hello_bytes.extend(ch)
                if ch == b'\n':
                    break
            hello = hello_bytes.decode('utf-8', errors='replace').strip()
            print(f"Received from peer_{remote_peer_id}: {hello}")

# ----- CLI -----
def main():
    parser = argparse.ArgumentParser(description="Simple peer 'client' performing handshake + hello")
    parser.add_argument("--id", type=int, required=True, help="This peer's ID (integer)")
    parser.add_argument("--host", required=True, help="Remote host to connect to")
    parser.add_argument("--port", type=int, required=True, help="Remote port to connect to")
    args = parser.parse_args()

    client = PeerClient(peer_id=args.id)
    client.connect_and_receive_hello(remote_host=args.host, remote_port=args.port)

if __name__ == "__main__":
    main()
