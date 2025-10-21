import threading
import socket
import random as r
import sys
import time
from dataclasses import dataclass
from queue import Queue, Empty
import math

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
class Peer:
    peerID: int
    hostname: str
    port: int
    hasFileFlag: bool
    active: bool = False
    receivedConnection:bool = False
    sending_socket: socket.socket | None = None
    handshake: bool = False
    recv_queue: Queue = field(default_factory=Queue)
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    bitfield = bytearray()
    newconnection: bool = False
    interested: bool = False
    choked: bool = False

    def __post_init__(self):
        self.peerID = int(self.peerID)
        self.port = int(self.port)
        self.hasFileFlag = bool(int(self.hasFileFlag))

class ConnectionManager:
    def __init__(self, app_ref):
        self.server_socket = app_ref.server_socket
        self.app_ref = app_ref  # reference to app (for callbacks)
        self.threads = []
        self.connections = []
        self.running = True

    def validate_handshake(self, data):
        valid = True
        if len(data) != HANDSHAKE_LEN:
            valid = False
            #INFOMESSAGE("Invalid length.")
    
        header = data[:18]
        zero_bits = data[18:28]
        peer_id_bytes = data[28:32]

        if header != HANDSHAKE_HEADER:
            valid = False
            #INFOMESSAGE("Invalid Header Bits.")
        
        if zero_bits != (b'\x00' * 10):
            valid = False
            #INFOMESSAGE("Invalid Zero Bits.")
        
        if valid:
            peer_id = int.from_bytes(peer_id_bytes, byteorder='big')
            for p in self.app_ref.peers:
                if peer_id != p.peerID:
                    valid = False
                else:
                    valid = True
                    break

        return valid
    
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


    def handle_client(self, conn:socket.socket, addr, stop_event):
        CONNECTIONMESSAGE(f"{addr} connected.")
        current_thread = threading.current_thread()
        peer_obj: Peer | None = None

        if not stop_event.is_set():
            try:
                # --- First: do handshake ---
                data = self.recv_exact(conn,HANDSHAKE_LEN)
                if not self.validate_handshake(data):
                    DISCONNECTIONMESSAGE(f"{addr} sent invalid handshake.")
                    conn.close()
                    return

                # Identify peer
                identified = False
                peer_id = int.from_bytes(data[28:32], byteorder='big')
                for p in self.app_ref.peers:
                    if p.peerID == peer_id:
                        identified = True
                        peer_obj = p
                        peer_obj.active = True
                        peer_obj.receivedConnection = True
                        peer_obj.newconnection = True
                        peer_obj.thread = current_thread
                        break
                    
                if not identified:
                    DISCONNECTIONMESSAGE(f"{addr} peer ID {peer_id} unknown.")
                    conn.close()
                    return
                
                # Notify the app
                INFOMESSAGE(f"Valid handshake from {addr}")

                # --- Now keep reading messages ---
                while not stop_event.is_set() and self.running:
                    data = self.recv_exact(conn,4)
                    if not data:
                        continue
                    length = int.from_bytes(data, byteorder='big')
                    msg_type = self.recv_exact(conn, 1)
                    if not msg_type:
                        continue
                    data+=msg_type
                    #Get the payload
                    payload = self.recv_exact(conn, length)
                    if not payload:
                        continue
                    data+=payload

                    # Push data to peer's queue
                    peer_obj.recv_queue.put(data)

            except Exception as e:
                DISCONNECTIONMESSAGE(f"{addr} error: {e}")
            finally:
                if peer_obj:
                    peer_obj.active = False
                conn.close()
                if current_thread in self.threads:
                    self.threads.remove(current_thread)
                DISCONNECTIONMESSAGE(f"{addr} disconnected.")

    def start(self, stop_event):
        self.server_socket.listen()
        self.server_socket.settimeout(1.0)  # Check every second
        INFOMESSAGE("Receiver thread started; listening for connections.")
        while not stop_event.is_set():
            try:
                conn, addr = self.server_socket.accept()
            except socket.timeout:
                continue
            #except OSError: #Socket Closed
            #    continue
            thread = threading.Thread(target=self.handle_client, args=(conn, addr, stop_event))
            thread.start()
            self.threads.append(thread)
            self.connections.append(conn)
        for c in self.connections:
            try:
                c.close()
            except:
                continue
        INFOMESSAGE("Receiver thread ending. No longer listening for connections.")
        INFOMESSAGE("The midpoint project has terminated. This function is currently bugged. We're working on it.")

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=0.1)

    def connect_to_peer(self, peer: Peer):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((peer.hostname, int(peer.port)))
            INFOMESSAGE(f"Connected to peer {peer.hostname}:{peer.port}")
            peer.sending_socket = s
            peer.active = True
            peer.newconnection = True
            # Start a receiver thread for this connection if needed
        except Exception as e:
            DISCONNECTIONMESSAGE(f"Failed to connect to {peer.hostname}:{peer.port} ({e})")
            peer.active = False

    def send_to_peer(self, peer: Peer, data: bytes):
        if not peer.sending_socket:
            DISCONNECTIONMESSAGE(f"Peer {peer.peerID} has no socket to send to.")
            return
        try:
            peer.sending_socket.sendall(data)
        except Exception as e:
            DISCONNECTIONMESSAGE(f"Failed to send to {peer.peerID}: {e}")
            peer.active = False
            try:
                peer.sending_socket.close()
            except:
                pass
            peer.sending_socket = None


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
        self.update_port("PeerInfo.cfg", self.peerid, port)
        self.CM = ConnectionManager(self)
        values = self.readConfig("Common.cfg")
        self.NumberOfPreferredNeighbors = values[0]
        self.UnchokingInterval = values[1]
        self.OptimisticUnchokingInterval = values[2]
        self.FileName = values[3]
        self.FileSize = values[4]
        self.PieceSize = values[5]
        self.peers = self.getPeersFromFile("PeerInfo.cfg")
        self.running = True
        self.calcBitfield(self.FileName)
        self.threads = []
        self.stop_event = threading.Event()

    def calcBitfield(self, filename:str):
        path = "./Configs/project_config_file_small/project_config_file_small/" + str(self.peerid)+"/"+filename
        
        total_pieces = math.ceil(int(self.FileSize) / int(self.PieceSize)) #Example: 10000232/32768
        num_bytes = math.ceil(total_pieces / 8) # 306

        bitfield = bytearray(num_bytes)

        hasFileFlag = False
        for p in self.peers:
            if p.peerID == self.peerid:
                if p.hasFileFlag:
                    hasFileFlag = True

        if hasFileFlag:
            for i in range(total_pieces):
                byte_index = i // 8
                bit_index = 7 - (i % 8)  # MSB first
                bitfield[byte_index] |= (1 << bit_index)
        else:
            # For now, all zeros
            pass

        self.bitfield = bytes(bitfield)
        INFOMESSAGE(f"Generated bitfield for {total_pieces} pieces ({num_bytes} bytes).")

    def updateBitfield(self, piece_index: int):
        "Update the bitfield by the piece number."
        byte_index = piece_index // 8
        bit_index = 7 - (piece_index % 8)  # MSB first
        
        # Convert to mutable bytearray
        bitfield_array = bytearray(self.bitfield)
        
        # Set the bit to 1 (mark piece as "have")
        bitfield_array[byte_index] |= (1 << bit_index)
        
        # Save back
        self.bitfield = bytes(bitfield_array)

        INFOMESSAGE(f"Updated bitfield: now have piece {piece_index}.")

    ## TODO: Change this to a process manager.
    ## The process will instead use a thread safe queue to tasks based on messages received.
    def managePeers(self, stop_event):
        count = 0
        print("This midpoint program will only run for approximately 30 seconds because the function is buggy.")
        while not stop_event.is_set():
            #This part of the code is in fact broken and it set to terminate After about 30 seconds of running.
            if count < 300:
                count += 1
                for peer in self.peers:
                    if peer.receivedConnection:
                            peer.receivedConnection = False
                            #This has to be done to make sure that the port is correct
                            #The port could be the last randomly picked one from the
                            #Last time the program ran, so we need to check before
                            #Connecting.
                            self.updatePeerPorts(self.peers, "PeerInfo.cfg")
                            self.connect_to_peer(peer)
                    if peer.active:
                        if peer.newconnection:
                            peer.newconnection = False
                            print(self.make_handshake())
                            self.CM.send_to_peer(peer, self.make_handshake())
                            self.CM.send_to_peer(peer, self.createMessage(5))
                        if peer.interested:
                            #Reset the interest.
                            #New interest will be determined when we get a have.
                            #Interest also needs to be recalculated when we receive a full piece.
                            peer.interested = False
                            self.CM.send_to_peer(peer, self.createMessage(2))
                            INFOMESSAGE(f"Interested Message sent to {peer.hostname}")
                        if not peer.choked:
                            pass
            else:
                break
            time.sleep(.1)
        self.stop()

    def createMessage(self, type):
        data = b''
        if type == 0: # Choke
            length_bytes = bytes([0])
            msg_id = bytes([0])
            data = length_bytes + msg_id
        if type == 1: # Unchoke
            length_bytes = bytes([0])
            msg_id = bytes([1])
            data = length_bytes + msg_id
        if type == 2: # Interested
            length_bytes = bytes([0])
            msg_id = bytes([2])
            data = length_bytes + msg_id
        if type == 3: # Not Interested
            length_bytes = bytes([0])
            msg_id = bytes([3])
            data = length_bytes + msg_id
        if type == 4: # Have
            length_bytes = bytes([0])
            msg_id = bytes([4])
            data = length_bytes + msg_id
        if type == 5:  # bitfield
            length_bytes = len(self.bitfield).to_bytes(4, byteorder='big')
            msg_id = bytes([5])
            data = length_bytes + msg_id + self.bitfield
        return data
    
    def determineInterest(self, peer:Peer) -> bool:
        """Return True if peer has at least one piece we don't."""
        my_bits = self.bitfield
        their_bits = peer.bitfield

        for i in range(len(my_bits)):
            # Has bit = 1 where we have 0
            if (their_bits[i] & ~my_bits[i]) != 0:
                return True
        return False  

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
    
    def updatePeerPorts(self, Peers:list[Peer], peer_path:str):
        ports = []
        addr = []
        with open(peer_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    #This will add ourselves to the list of peers, but we will use that
                    #to determine the active peers before we started.
                    continue
                #<peerID> <hostname/IP> <port> <hasFileFlag>
                addr.append(parts[1])
                ports.append(parts[2])
        for i in range(len(Peers)):
            Peers[i].port = ports[i]
            Peers[i].hostname = addr[i]

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

    def process_incoming_messages(self, stop_event):
        """
        Runs in a separate thread or main loop to process messages.
        """
        while not stop_event.is_set():
            for peer in self.peers:
                if peer.active:
                    try:
                        msg = peer.recv_queue.get_nowait()
                        self.handle_message(peer, msg)
                    except Empty:
                        continue
            time.sleep(0.01)  # Prevent busy wait

    def handle_message(self, peer:Peer, msg):
        #This will handle all the different messages based on type.
        msg_type = msg[4]
        match msg_type:
            case 0: #Choke
                pass
            case 1: #Unchoke
                pass
            case 2: #interested
                pass
            case 3: #Not interested
                pass
            case 4: #Have
                pass
            case 5: #Bitfield
                payload = msg[5:]
                peer.bitfield = bytearray(payload)
                peer.interested = self.determineInterest(peer)
                INFOMESSAGE(f"Bitfield for Peer {peer.peerID} has been set.")
            case 6: #Request
                pass
            case 7: #Piece
                pass
            case -1:#Received handshake
                pass
        
    def connect_to_initial_peers(self):
        """
        The first thing a client should do is connected to available peers
        In this simple case, the available peers are the peers listed above the
        current app's peer ID in the list
        """
        for p in self.peers:
            #This will loop in order until we hit our own peerid.
            if p.peerID != self.peerid:
                self.CM.connect_to_peer(p)
            else:
                break

    def check_complete(self):
        pass

    def start(self):
        self.threads.append(threading.Thread(target=self.CM.start, args=(self.stop_event,)))
        self.threads.append(threading.Thread(target=self.process_incoming_messages, args=(self.stop_event,)))
        self.threads.append(threading.Thread(target=self.managePeers, args=(self.stop_event,)))
        self.connect_to_initial_peers()
        for t in self.threads:
            t.start()

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.CM.stop()

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
                    parts[1] = self.hostname
                    parts[2] = str(new_port)
                    updated_line = " ".join(parts)
                else:
                    updated_line = line.strip()

                updated_lines.append(updated_line)

        # Write the updated config file back
        with open(config_path, 'w') as f:
            f.write("\n".join(updated_lines) + "\n")

        print(f"[INFO] Updated peer {peer_id} to use port {new_port}.")
        
    def connect_to_peer(self, peer:Peer):
        self.CM.connect_to_peer(peer)

    def make_handshake(self):
        return (HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + self.peerid.to_bytes(4, byteorder='big'))

if __name__ == "__main__":
    PEERID = int(sys.argv[1])
    a = app(PEERID)
    a.start()