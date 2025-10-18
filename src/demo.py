import socket
import threading
import time

LOCAL_IP = "192.168.254.125"
PORT = 5050


class ConnectionManager:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connections = {}  # {address: socket}
        self.running = True

        # Start listening thread
        threading.Thread(target=self._listen, daemon=True).start()

    def _listen(self):
        """Accept incoming connections."""
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
        """Background receiver loop for a single connection."""
        while self.running:
            try:
                data = conn.recv(1024)
                if not data:
                    print(f"[DISCONNECT] {addr} closed the connection.")
                    break
                print(f"[RECV from {addr}] {data.decode()}")
            except ConnectionResetError:
                print(f"[ERROR] Connection reset by {addr}")
                break
            except OSError:
                break
        conn.close()
        if addr in self.connections:
            del self.connections[addr]

    def send_to_all(self, message):
        """Send a message to all connected peers."""
        for addr, conn in list(self.connections.items()):
            try:
                conn.sendall(message.encode())
                print(f"[SEND -> {addr}] {message}")
            except OSError:
                print(f"[ERROR] Failed to send to {addr}")

    def stop(self):
        self.running = False
        for conn in self.connections.values():
            conn.close()


def main():
    manager = ConnectionManager(LOCAL_IP, PORT)

    # Give the listener a moment to start
    time.sleep(1)

    # Connect to itself (simulating another peer)
    manager.connect_to_peer(LOCAL_IP, PORT)

    # Wait a bit for the connection to establish
    time.sleep(1)

    # Send messages to all connected peers
    manager.send_to_all("Hello from main thread!")
    time.sleep(1)
    manager.send_to_all("Another message later!")

    # Keep running
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
