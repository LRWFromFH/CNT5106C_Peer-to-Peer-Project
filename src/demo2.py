import socket
import threading
import time
import argparse

LOCAL_IP = "127.0.0.1"

# ----- Constants derived from the project specification -----
HANDSHAKE_HEADER = b'P2PFILESHARINGPROJ'  # 18 bytes
HANDSHAKE_ZERO_BITS = 10                  # 10 zero bytes
HANDSHAKE_LEN = 18 + 10 + 4               # 32 total bytes

class ConnectionManager:
    def __init__(self, ip, port, peerid):
        self.ip = ip
        self.port = port
        self.peerid = int(peerid)      
        self.connections = {}  # {addr: socket}
        self.remote_ids = {}
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
            try:
                # 1) Receive their 32-byte handshake
                hs = self.recv_exact(conn, HANDSHAKE_LEN)
                if not hs or not self.validate_handshake(hs):
                    print(f"[ERROR] Bad handshake from {addr}")
                    conn.close()
                    continue

                # 2) Extract remote peer id (optional but useful)
                remote_id = int.from_bytes(hs[28:32], 'big')

                # 3) Send our handshake back
                conn.sendall(self.make_handshake())

                print(f"[LISTENER] Handshake OK from id={remote_id} at {addr}")

                # 4) Now that handshake is done, track the conn and start recv loop
                self.connections[addr] = conn
                print(f"[LISTENER] New connection from {addr}")
                self.connections[addr] = conn
                threading.Thread(target=self._recv_loop, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"[ERROR] Handshake failed from {addr}: {e}")
                try:
                    conn.close()
                except:
                    pass
                continue

    def connect_to_peer(self, host, port):
        """Connect to another peer."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            self.connections[(host, port)] = s
            s.sendall(self.make_handshake())
            hs = self.recv_exact(s, HANDSHAKE_LEN)
            if not hs or not self.validate_handshake(hs):
                s.close()
                print(f"[ERROR] Bad handshake from {host}:{port}")
                return

            remote_id = int.from_bytes(hs[28:32], 'big')
            print(f"[CONNECT] Handshake OK with peer id={remote_id} at {host}:{port}")

            key = (host, port)
            self.connections[key] = s
            self.remote_ids[key] = remote_id

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

    def recv_exact(self,conn, length):
        """Receive exactly `length` bytes or return None if connection closed."""
        buffer = b''
        while len(buffer) < length:
            chunk = conn.recv(length - len(buffer))
            if not chunk:
                # Socket closed before full message
                return None
            buffer += chunk
        return buffer

    #Handshake Functions
    def make_handshake(self):
        return (HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + self.peerid.to_bytes(4, byteorder='big'))

    def validate_handshake(self, data):
        if len(data) != HANDSHAKE_LEN:
            return False
    
        header = data[:18]
        zero_bits = data[18:28]

        if header != HANDSHAKE_HEADER:
            return False
        
        if zero_bits != (b'\x00' * 10):
            return False
        
        return True
    



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True)
    args = parser.parse_args()

    # Give each process its own port
    base_port = 5050
    my_port = base_port + args.id
    manager = ConnectionManager(LOCAL_IP, my_port,  args.id)

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
