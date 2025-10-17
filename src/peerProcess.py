import threading
import socket
import random as r
import sys
import time
from dataclasses import dataclass

# ----- Constants derived from the project specification -----
HANDSHAKE_HEADER = b'P2PFILESHARINGPROJ'  # 18 bytes
HANDSHAKE_ZERO_BITS = 10                  # 10 zero bytes
HANDSHAKE_LEN = 18 + 10 + 4               # 32 total bytes

def INFOMESSAGE(text:str) -> None:
    "Prints information about socket to terminal."
    print(f"[INFO] {text}")

def CONNECTIONMESSAGE(text:str) -> None:
    """
    Prints information about connections to terminal. 
    This can be generic messages about connections as well.
    """
    print(f"[CONNECTION] {text}")

def DISCONNECTIONMESSAGE(text:str) -> None:
    "Prints information about connections to terminal."
    print(f"[DISCONNECTION] {text}")

from dataclasses import dataclass, field
import threading
import socket

@dataclass
class Peer:  # <peerID> <hostname/IP> <port> <hasFileFlag>
    peerID: int
    hostname: str
    port: int
    hasFileFlag: bool
    active: bool = False
    conn: socket.socket | None = None
    thread: threading.Thread | None = None
    handshake: bool = False

    def __post_init__(self):
        self.peerID = int(self.peerID)
        self.port = int(self.port)
        self.hasFileFlag = bool(int(self.hasFileFlag))

class Receiver:

    server_socket:socket.socket

    def __init__(self, server_socket, app_ref):
        self.server_socket = server_socket
        self.app_ref = app_ref  # reference to app (for callbacks)
        self.threads = []
        self.running = True

    def validate_handshake(self, data):
        if len(data) != HANDSHAKE_LEN:
            return False
    
        header = data[:18]
        zero_bits = data[18:28]
        peer_id_bytes = data[28:32]

        if header != HANDSHAKE_HEADER:
            return False
        
        if zero_bits != (b'\x00' * 10):
            return False

        try:
            peer_id = int.from_bytes(peer_id_bytes, byteorder='big')
            if self.app_ref.peers[peer_id] == peer_id:
                return True
        except Exception:
            return False

        return True

    def handle_client(self, conn:socket.socket, addr):
        CONNECTIONMESSAGE(f"{addr} connected.")
        current_thread = threading.current_thread()
        connected = True
        handshakeAttempted = False #Check if handshake has happened.
        while connected:
            try:
                if not handshakeAttempted:
                    data = conn.recv(HANDSHAKE_LEN)
                    if data:
                        if self.validate_handshake(data):
                            self.app_ref.on_handshake_valid(addr, conn)
                        else:
                            DISCONNECTIONMESSAGE(f"{addr} sent invalid handshake.")
                            conn.close()
            except Exception as e:
                DISCONNECTIONMESSAGE(f"{addr} error: {e}")
            finally:
                conn.close()
                if current_thread in self.threads:
                    self.threads.remove(current_thread)

    def start(self):
        self.server_socket.listen()
        self.server_socket.settimeout(1.0)  # Check every second
        INFOMESSAGE("Receiver thread started; listening for connections.")
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            #except OSError: #Socket Closed
            #    continue
            thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
            thread.start()
            self.threads.append(thread)
        INFOMESSAGE("Receiver thread ending. No longer listening for connections.")

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=0.1)

class Sender:
    def __init__(self, app_ref):
        self.app_ref = app_ref

    def connect_to_peer(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            INFOMESSAGE(f"Connected to peer {host}:{port}")
            # Example handshake send
            s.sendall(HANDSHAKE_HEADER + b'\x00' * HANDSHAKE_ZERO_BITS + b'\x01\x02\x03\x04')
        except Exception as e:
            DISCONNECTIONMESSAGE(f"Failed to connect to {host}:{port} ({e})")
        finally:
            s.close()

class app:
    
    "This is going to be the overall app and where data will be passed up to and down from."
    def __init__(self, PEERID):
        self.hostname = socket.gethostbyname(socket.gethostname())
        self.peerid = PEERID
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            port = r.randint(2000, 6000)
            try:
                self.server_socket.bind((self.hostname, port))
                break  # Success! Exit loop.
            except OSError:
                continue  # Port already in use — try again.
        INFOMESSAGE(f"Server bound on {self.hostname}:{port}")
        self.update_port("./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg", self.peerid, port)
        self.sender = Sender(self)
        self.receiver = Receiver(self.server_socket, self)
        self.make_handshake()
        values = self.readConfig("./Configs/project_config_file_small/project_config_file_small/Common.cfg")
        self.NumberOfPreferredNeighbors = values[0]
        self.UnchokingInterval = values[1]
        self.OptimisticUnchokingInterval = values[2]
        self.FileName = values[3]
        self.FileSize = values[4]
        self.PieceSize = values[5]
        Peers = self.getPeersFromFile("./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg")
        self.peers: dict[int, Peer] = {
            p.peerID: p for p in Peers if p.peerID != self.peerid
        }

    def readConfig(self, config_path):
        values = []
        with open(config_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                values.append(parts[1])
                #NumberOfPreferredNeighbors 3
                #UnchokingInterval 5
                #OptimisticUnchokingInterval 10
                #FileName thefile
                #FileSize 2167705
                #PieceSize 16384
        return values

    def getPeersFromFile(self, peer_path:str):
        Peers = []
        with open(peer_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    #This will add ourselves to the list of peers, but we will use that
                    #to determine the active peers before we started.
                    continue
                #<peerID> <hostname/IP> <port> <hasFileFlag>
                Peers.append(Peer(parts[0], parts[1], parts[2], parts[3]))
        return Peers

    def peer_management_loop(self):
        pass

    def check_complete(self):
        pass

    def start(self):
        threading.Thread(target=self.receiver.start).start()
        #threading.Thread(target=self.peer_management_loop, daemon=True).start()

    def update_port(self,config_path: str, peer_id: int, new_port: int):
        """
        Updates the port number for a given peer ID in the config file.
        This is necessary for the local peers to find out what ports to connect to.
        Since they use the PeerInfo.cfg file.
        """
        updated_lines = []

        with open(config_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue

                # Check if this line matches the peer ID
                if parts[0] == str(peer_id):
                    # Replace the port (3rd value)
                    parts[2] = str(new_port)
                    updated_line = " ".join(parts)
                else:
                    updated_line = line.strip()

                updated_lines.append(updated_line)

        # Write the updated config file back
        with open(config_path, 'w') as f:
            f.write("\n".join(updated_lines) + "\n")

        print(f"[INFO] Updated peer {peer_id} to use port {new_port}.")


    # CALLBACK from receiver
    def on_handshake_valid(self, addr, conn):
        INFOMESSAGE(f"Valid handshake from {addr}")
        # Example: respond, register peer, or send a file piece request
        pass

    def connect_to_peer(self, host, port):
        self.sender.connect_to_peer(host, port)

    def make_handshake(self):
        return (HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + PEERID.to_bytes(4, byteorder='big'))

if __name__ == "__main__":
    PEERID = int(sys.argv[1])
    a = app(PEERID)
    a.start()