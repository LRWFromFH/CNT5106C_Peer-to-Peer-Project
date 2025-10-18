import socket
import threading
import time
import argparse

LOCAL_IP = "192.168.254.125"


class ConnectionManager:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connections = {}  # {addr: socket}
        self.running = True

        # Start listener thread
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.listen()
        print(f"[LISTENER] Listening on {self.ip}:{self.port}")

        while self.running:
            conn, addr = server.accept()
            print(f"[LISTENER] New connection from {addr}")
            self.connections[addr] = conn
            threading.Thread(target=self._recv_loop, args=(conn, addr), daemon=True).start()

    def connect_to_peer(self, host, port):
        """Connect to another peer."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            self.connections[(host, port)] = s
            print(f"[CONNECT] Connected to peer {host}:{port}")
            threading.Thread(target=self._recv_loop, args=(s, (host, port)), daemon=True).start()
        except Exception as e:
            print(f"[ERROR] Could not connect to {host}:{port}: {e}")

    def _recv_loop(self, conn, addr):
        while self.running:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"[DISCONNECT] {addr} closed connection.")
                    break
                print(f"[RECV from {addr}] {data.decode()}")
            except Exception:
                break
        conn.close()
        if addr in self.connections:
            del self.connections[addr]

    def send_to_all(self, message):
        for addr, conn in list(self.connections.items()):
            try:
                conn.sendall(message.encode())
                print(f"[SEND -> {addr}] {message}")
            except Exception as e:
                print(f"[ERROR] Could not send to {addr}: {e}")

    def stop(self):
        self.running = False
        for conn in list(self.connections.values()):
            conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True)
    args = parser.parse_args()

    # Give each process its own port
    base_port = 6001
    my_port = base_port + args.id
    manager = ConnectionManager(LOCAL_IP, my_port)

    time.sleep(1)

    # Example: each peer tries to connect to the next one
    target_port = base_port + (args.id % 2) + 1  # simple 2-peer setup
    if target_port != my_port:
        time.sleep(1)
        manager.connect_to_peer(LOCAL_IP, target_port)

    # Wait for things to connect
    time.sleep(2)

    # Send some messages
    manager.send_to_all(f"Hello from Peer {args.id}")
    time.sleep(1)
    manager.send_to_all(f"Another message from Peer {args.id}")

    # Keep running
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
