import threading
import socket
import random as r
import sys
import time
from dataclasses import dataclass, field
from queue import Queue, Empty
import math
from enum import Enum
import random

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

class Messages(Enum):
    CHOKE           = 0
    UNCHOKE         = 1
    INTERESTED      = 2
    NOT_INTERESTED  = 3
    HAVE            = 4
    BITFIELD        = 5
    REQUEST         = 6
    PIECE           = 7
    HANDSHAKE       = -1
    CONNECT_TO      = -2

    @staticmethod
    def get_type(m_type:str):
        try:
            m_type = int(m_type)
            for m in Messages:
                if m.value == m_type:
                    return m
            return None
        except Exception as e:
            print(f"Error: {e}")

@dataclass
class Peer:
    peerID: int
    hostname: str
    port: int
    hasFileFlag: bool
    sending_socket: socket.socket | None = None
    recv_queue: Queue = field(default_factory=Queue)
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    thread: threading.Thread | None = None
    bitfield = bytearray()
    newconnection: bool = False
    interested: bool = False
    choked: bool = True
    chokingUs: bool = True
    connected:bool = False
    datasent:int = 0 # The number of pieces of file a Peer
    tiebreak:float = 0 # Random number between 0-1, used to randomly select between two peers with same datasent scores
    unchokescore:int = 0
    last_rate_time: float | None = None
    current_rate_bps:float = 0
    bytes_received:int = 0
    bytes_at_last_calc:int = 0

    def __post_init__(self):
        self.peerID = int(self.peerID)
        self.port = int(self.port)
        self.hasFileFlag = bool(int(self.hasFileFlag))

    # New functions for choking logic
    def unchoke(self):
        self.choked = False
        self.datasent = 0
        self.unchokescore = 0

    def gotdata(self):
        self.datasent += 1

    def settiebreak(self):
        self.tiebreak = random.random()

    def getunchokescore(self):
        self.settiebreak()
        self.unchokescore = self.current_rate_bps
        return self.unchokescore

class ConnectionManager:
    def __init__(self, app_ref:"app"):
        self.server_socket = app_ref.server_socket
        self.app_ref = app_ref  # reference to app (for callbacks)
        self.threads = []
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
    
    def recv_exact(self, conn:socket.socket, length, peer_obj:Peer=None):
        """Receive exactly `length` bytes or return None if connection closed."""
        old_timeout = conn.gettimeout()
        
        buffer = b''
        conn.settimeout(0.5)  # temporary timeout

        while len(buffer) < length and self.running:
            try:
                chunk = conn.recv(length - len(buffer))
                if not chunk:
                    # Socket closed before full message
                    return None
                buffer += chunk

                if peer_obj is not None:
                    peer_obj.bytes_received += len(chunk)
            except socket.timeout:
                continue  # check running flag
            except OSError:
                return None

        conn.settimeout(old_timeout)
        return buffer if self.running else None


    def handle_client(self, conn:socket.socket, addr):
        CONNECTIONMESSAGE(f"{addr} connected.")
        current_thread = threading.current_thread()
        peer_obj: Peer | None = None
        now = time.time()

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
                    peer_obj.thread = current_thread
                    peer_obj.last_rate_time = now
                    peer_obj.bytes_received += len(data)
                    break
                
            if not identified:
                #raise Exception(f"{addr} peer ID {peer_id} unknown.")
                conn.close()
                return
            
            # Notify the app
            INFOMESSAGE(f"Valid handshake from {addr}")
            peer_obj.connected = True
            self.app_ref.messageQueue.put((peer_obj, Messages.HANDSHAKE, None))

            # --- Now keep reading messages ---
            while self.running and peer_obj.connected:
                now = time.time()
                elapsed = now - peer_obj.last_rate_time
                
                data = self.recv_exact(conn,4)
                if not data:
                    continue
                peer_obj.bytes_received += len(data)
                length = int.from_bytes(data, byteorder='big')
                msg_type = Messages.get_type(int.from_bytes(self.recv_exact(conn, 1),byteorder='big'))
                if not msg_type:
                    continue
                peer_obj.bytes_received += 1
                #Get the payload
                if length != 0:
                    payload = self.recv_exact(conn, length)
                    if payload:
                        peer_obj.bytes_received += length

                else:
                    payload = None
                
                #Check data rate
                now = time.time()
                elapsed = now - peer_obj.last_rate_time
                if elapsed >= 1.0:
                    delta = peer_obj.bytes_received - peer_obj.bytes_at_last_calc
                    peer_obj.current_rate_bps = round(delta / elapsed,2)
                    peer_obj.bytes_at_last_calc = peer_obj.bytes_received
                    peer_obj.last_rate_time = now
                INFOMESSAGE(f"BPS of Peer {peer_obj.peerID}: {peer_obj.current_rate_bps} bps.")

                # Push data to peer's queue
                #peer_obj.recv_queue.put(data)
                self.app_ref.messageQueue.put((peer_obj, msg_type, payload))

        except Exception as e:
            DISCONNECTIONMESSAGE(f"{addr} error: {e}")
        finally:
            conn.close()
            if current_thread in self.threads:
                self.threads.remove(current_thread)
            DISCONNECTIONMESSAGE(f"{addr} disconnected.")

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
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            self.threads.append(thread)
        INFOMESSAGE("Receiver thread ending. No longer listening for connections.")

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=0.1)

    def stop_thread(self, peer:Peer):
        for t in self.threads:
            if t == peer.thread:
                t.join(timeout=0.1)
        
    def disconnect_from_peer(self, peer:Peer):
        try:
            #Potentially change boolean connection to false instead of joining thread
            #The Handle client will close the socket and remove the thread by default.
            peer.connected = False
            peer.sending_socket.close()
            self.stop_thread(peer)
        except:
            INFOMESSAGE(f"Could not close connections with peer {peer.peerID} on {peer.hostname}:{peer.port}")

    def connect_to_peer(self, peer: Peer):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((peer.hostname, int(peer.port)))
            INFOMESSAGE(f"Connected to peer {peer.hostname}:{peer.port}")
            peer.sending_socket = s
            # Start a receiver thread for this connection if needed
        except Exception as e:
            DISCONNECTIONMESSAGE(f"Failed to connect to {peer.hostname}:{peer.port} ({e})")

    def send_to_peer(self, peer: Peer, data: bytes):
        with peer.send_lock:
            if not peer.sending_socket:
                DISCONNECTIONMESSAGE(f"Peer {peer.peerID} has no socket to send to.")
                return
            try:
                peer.sending_socket.sendall(data)
            except Exception as e:
                DISCONNECTIONMESSAGE(f"Failed to send to {peer.peerID}: {e}")
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
        self.update_host("./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg", self.peerid, port)
        self.CM = ConnectionManager(self)
        values = self.readConfig("./Configs/project_config_file_small/project_config_file_small/Common.cfg")
        self.NumberOfPreferredNeighbors = values[0]
        self.UnchokingInterval = values[1]
        self.OptimisticUnchokingInterval = values[2]
        self.FileName = values[3]
        self.FileSize = values[4]
        self.PieceSize = values[5]
        self.peers = self.getPeersFromFile("./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg")
        self.running = True
        self.calcBitfield(self.FileName)
        self.messageQueue = Queue()
        self.dispatchQueue = Queue()
        self.have_count = 0
        self.connectedPeers = []
        self.OptimisticallyUnchokedPeer:Peer = None
        self.UnchokedPeers = []
        self.hasCompleteFile = None


    def calcBitfield(self, filename:str):
        path = "./Configs/project_config_file_small/project_config_file_small/" + str(self.peerid)+"/"+filename
        
        total_pieces = math.ceil(int(self.FileSize) / int(self.PieceSize)) #Example: 2167705/16384 = 133
        num_bytes = math.ceil(total_pieces / 8) # 17

        bitfield = bytearray(num_bytes)

        hasFileFlag = False
        for p in self.peers:
            if p.peerID == self.peerid:
                if p.hasFileFlag:
                    hasFileFlag = True
                    total_pieces = math.ceil(int(self.FileSize) / int(self.PieceSize))
                    self.have_count = total_pieces
                    self.hasCompleteFile = True

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

    def updateBitfield(self, peer:Peer, piece_index: int):
        "Update the bitfield by the piece number."
        if peer:
            bitfield = peer.bitfield
        else:
            bitfield = self.bitfield
        byte_index = piece_index // 8
        bit_index = 7 - (piece_index % 8)  # MSB first
        
        # Convert to mutable bytearray
        bitfield_array = bytearray(bitfield)
        
        # Set the bit to 1 (mark piece as "have")
        bitfield_array[byte_index] |= (1 << bit_index)
        
        # Save back
        if peer:
            peer.bitfield = bytes(bitfield_array)
        else:
            self.bitfield = bytes(bitfield_array)
            # Update count how pieces we have
            self.have_count += 1

        INFOMESSAGE(f"Updated bitfield: now have piece {piece_index}.")

    ## TODO: Change this to a process manager.
    ## The process will instead use a thread safe queue to tasks based on messages received.
    def managePeers(self):
        while self.running:
            p:Peer
            try:
                peer:Peer
                msg_type:Messages
                payload:int
                peer, msg_type, payload = self.dispatchQueue.get_nowait()

                match msg_type:
                    #We have to connect to
                    case Messages.CONNECT_TO:
                        self.updatePeerPorts(self.peers, "./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg")
                        INFOMESSAGE(f"Connecting to peer {peer.peerID} @{peer.hostname}:{peer.port}")
                        self.CM.connect_to_peer(peer)
                        self.CM.send_to_peer(peer, self.make_handshake())
                        self.CM.send_to_peer(peer, self.createMessage(Messages.BITFIELD))
                        self.connectedPeers.append(peer)
                    #This means that we have received a handshake from the peer.
                    #We do not necessarily have to return the handshake
                    case Messages.HANDSHAKE:
                        #Connect to the peer and return a handshake and bitfield if we do NOT already have a sending socket for the peer.
                        if not peer.sending_socket:
                            self.updatePeerPorts(self.peers, "./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg")
                            self.CM.connect_to_peer(peer)
                            self.CM.send_to_peer(peer, self.make_handshake())
                            self.CM.send_to_peer(peer, self.createMessage(Messages.BITFIELD))
                            self.connectedPeers.append(peer)
                        #If we receive a handshake, but already have a connection to them, then we can safely ignore it.
                    #We have received a bitfield from and need to simply determine interest in the sender's pieces.
                    #The bitfield has already been set for the peer.
                    case Messages.BITFIELD:
                        #print(f"Result of interest check: {self.determineInterest(peer)}")
                        if self.determineInterest(peer):
                            self.dispatchQueue.put((peer, Messages.INTERESTED, None))
                        else:
                            self.dispatchQueue.put((peer, Messages.NOT_INTERESTED, None))
                    #Whatever we want to do when we receive an interested message.
                    case Messages.INTERESTED:
                        self.CM.send_to_peer(peer, self.createMessage(Messages.INTERESTED))
                        INFOMESSAGE(f"Sending INTERESTED to peer {peer.peerID} @{peer.hostname}:{peer.port}")
                    case Messages.NOT_INTERESTED:
                        self.CM.send_to_peer(peer, self.createMessage(Messages.NOT_INTERESTED))
                        INFOMESSAGE(f"Sending NOT_INTERESTED to peer {peer.peerID} @{peer.hostname}:{peer.port}")
                    case Messages.HAVE: # TODO Implement proper cases for Have, Bitfield, Request, and Piece
                        self.CM.send_to_peer(peer, self.createMessage(Messages.HAVE, payload))
                        INFOMESSAGE(f"Sending HAVE message from peer {peer.peerID} @{peer.hostname}:{peer.port}")
                        #If we receive a have message, we need to update the bitfield for that peer.
                    case Messages.REQUEST:
                        #Asking for piece
                        self.CM.send_to_peer(peer, self.createMessage(Messages.REQUEST, payload))
                        #We have received a request message and should determine if they are unchoked/can be sent to.
                        INFOMESSAGE(f"Sending REQUEST message from peer {peer.peerID} @{peer.hostname}:{peer.port}")
                    case Messages.PIECE:
                        #This is the case that we have received a piece from a peer, we need to update our own bitfield.
                        #This should not get sent to us if we have the complete file
                        self.CM.send_to_peer(peer, self.createMessage(Messages.PIECE, payload))
                        INFOMESSAGE(f"Sending PIECE message to peer {peer.peerID} @{peer.hostname}:{peer.port}")
                    case Messages.CHOKE:
                        self.CM.send_to_peer(peer, self.createMessage(Messages.CHOKE))
                    case Messages.UNCHOKE:
                        self.CM.send_to_peer(peer, self.createMessage(Messages.UNCHOKE))
                    case _:
                        print(peer, msg_type)
                        INFOMESSAGE("Manage Peers: Unknown message type.")

            except Empty:
                continue

            #for peer in self.peers:
            #    if peer.receivedConnection:
            #            peer.receivedConnection = False
            #            #This has to be done to make sure that the port is correct
            #            #The port could be the last randomly picked one from the
            #            #Last time the program ran, so we need to check before
            #            #Connecting.
            #            self.updatePeerPorts(self.peers, "./Configs/project_config_file_small/project_config_file_small/PeerInfo.cfg")
            #            self.connect_to_peer(peer)
            #    if peer.active:
            #        if peer.newconnection:
            #            peer.newconnection = False
            #            print(self.make_handshake())
            #            self.CM.send_to_peer(peer, self.make_handshake())
            #            self.CM.send_to_peer(peer, self.createMessage(5))
            #        if peer.interested:
            #            #Reset the interest.
            #            #New interest will be determined when we get a have.
            #            #Interest also needs to be recalculated when we receive a full piece.
            #            peer.interested = False
            #            self.CM.send_to_peer(peer, self.createMessage(2))
            #            INFOMESSAGE(f"Interested Message sent to {peer.hostname}")
            #        if not peer.choked:
            #            pass

            #TODO: Remove this sleep if the manager is too slow.
            time.sleep(.1)

    def unchokingLoop(self):
        while(self.running):

            #Choke all peers
            c:Peer
            for c in self.connectedPeers:
                if c != self.OptimisticallyUnchokedPeer:
                    c.choked = True

            time.sleep(int(self.UnchokingInterval))
            INFOMESSAGE("Unchoking peers")
            NewUnchokedPeers = []
            #Unchoke random peer if seeder
            if(self.hasCompleteFile):
                #for number of preferredneighbors
                for i in range(int(self.NumberOfPreferredNeighbors)):
                    #This sets peer.choke = False
                    p = self.unchokeRandomPeer()
                    #Could be None, so if none, break. There are no peers to unchoke.
                    if p:
                        NewUnchokedPeers.append(p)
                    else:
                        break
            else:
                for i in range(int(self.NumberOfPreferredNeighbors)):
                    p = self.unchokePreferredPeer()
                    if p:
                        NewUnchokedPeers.append(p)
                    else:
                        break
            for c in self.connectedPeers:
                if c.choked:
                    #Put choke message on dispatch queue.
                    self.dispatchQueue.put((c,Messages.CHOKE,None))
                else:
                    #Put unchoke message on dispatch queue.
                    self.dispatchQueue.put((c,Messages.UNCHOKE,None))

            #for n in NewUnchokedPeers:
            #    if n not in self.UnchokedPeers:
            #        self.choke(n)
            #for p in self.UnchokedPeers:
            #    print(p)
            #    print(NewUnchokedPeers)
            #    if p in NewUnchokedPeers:
            #        continue
            #    #rechoke = True
            #    #for q in NewUnchokedPeers:
            #    #    if(q == p or p == None):
            #    #        rechoke = False
            #    #        break
            #    #if(not(rechoke)):
            #    #    continue
            #    self.choke(p)
            #self.UnchokedPeers = NewUnchokedPeers

    def optimisticUnchokingLoop(self):
        while(self.running):
            time.sleep(int(self.OptimisticUnchokingInterval))
            INFOMESSAGE("Optimistically unchoking peer")
            if self.OptimisticallyUnchokedPeer:
                self.OptimisticallyUnchokedPeer.choked = True
            NewOptimisticallyUnchokedPeer = self.unchokeRandomPeer()
            if(not(self.OptimisticallyUnchokedPeer == NewOptimisticallyUnchokedPeer) and not(self.OptimisticallyUnchokedPeer == None)):
                self.choke(self.OptimisticallyUnchokedPeer)
                self.OptimisticallyUnchokedPeer = NewOptimisticallyUnchokedPeer

    def unchokeRandomPeer(self, k=[]):
        ChokedPeers = self.getChokedPeers()
        if not(k==None):
            for i in k:
                ChokedPeers.append(i)
        if(len(ChokedPeers) == 0):
            INFOMESSAGE("No peers to unchoke")
            return None
        peer = r.choice(ChokedPeers)
        self.unchoke(peer)
        return peer

    def unchokePreferredPeer(self, k=None, l = None):
        if l == None:
            l = []
        if k == None:
            k = []

        ChokedPeers = self.getChokedPeers()
        for i in k:
            ChokedPeers.append(i)
        for i in l:
            for j in ChokedPeers:
                if(j==i):
                    ChokedPeers.remove(j)

        if(len(ChokedPeers) == 0):
            INFOMESSAGE("No peers to unchoke")
            return None
        peer = self.getPreferredPeer()
        self.unchoke(peer)
        return peer

    def getPreferredPeer(self):
        ChokedPeers = self.getChokedPeers()
        if(len(ChokedPeers) == 0):
            INFOMESSAGE("No preferred peer")
            return
        peer = ChokedPeers[0]
        score = peer.getunchokescore()
        for p in ChokedPeers:
            s = p.getunchokescore()
            if s > score:
                peer = p
            elif s == score:
                if p.tiebreak > peer.tiebreak:
                    peer = p
        return peer


    def createMessage(self, type:Messages, index:int=None):
        data = b''
        match type:
            case Messages.CHOKE:
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([0])
                data = length_bytes + msg_id
            case Messages.UNCHOKE: # Unchoke
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([1])
                data = length_bytes + msg_id
            case Messages.INTERESTED: # Interested
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([2])
                data = length_bytes + msg_id
            case Messages.NOT_INTERESTED: # Not Interested
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([3])
                data = length_bytes + msg_id
            case Messages.HAVE: # Have
                #TODO: Implement correct version of HAVE
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([4])
                data = length_bytes + msg_id
            case Messages.BITFIELD:  # bitfield
                length_bytes = len(self.bitfield).to_bytes(4, byteorder='big')
                msg_id = bytes([5])
                data = length_bytes + msg_id + self.bitfield
            case Messages.REQUEST:  # request
                length_bytes = (4).to_bytes(4, byteorder='big')
                msg_id = bytes([6])
                data = length_bytes + msg_id 
            case Messages.PIECE:  # piece
                #TODO: Implement file IO calls here to send bytes.
                #length_bytes = int(self.PieceSize).to_bytes(4, byteorder='big')
                length_bytes = (0).to_bytes(4, byteorder='big')
                msg_id = bytes([7])
                data = length_bytes + msg_id 
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
    
    def getNeededPieces(self, peer:Peer):
        our_bitfield = self.bitfield
        their_bitfield = peer.bitfield
        neededbits = []
        if not(len(self.bitfield) == len(peer.bitfield)):
            INFOMESSAGE("Bitfields different lengths")
            return
        
        for i in range(len(self.bitfield)):
            our_byte = our_bitfield[i]
            their_byte = their_bitfield[i]

            diff = ((~our_byte) & 0xFF) & their_byte
            if diff == 0:
                continue

            for j in range(8):
                if(diff & (1 << (7-j))):
                    index = 8*i + j
                    neededbits.append(index)

        return neededbits

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
    
    def findPeer(self, peerid:int):
        for peer in self.peers:
            if int(peer.peerID) == int(peerid): 
                return peer
        #INFOMESSAGE(f"Couldn't find peer with ID {peerid}")
        return 0
    
    def getConnectedPeers(self):
        return [p for p in self.peers if getattr(p, "connected", False)]
    
    def getChokedPeers(self):
        return [p for p in self.peers if getattr(p, "choked", True) and getattr(p, "connected", True) and getattr(p, "interested", True)]
        
    def getUnchokedPeers(self):
        return [p for p in self.peers if not(getattr(p, "choked", False)) and getattr(p, "connected", True) and getattr(p, "interested", True)]
    
    def choke(self, peer:Peer):
        if(peer==None):
            INFOMESSAGE("Cannot choke Nonetype")
            return
        INFOMESSAGE(f"Choked {peer.peerID}")
        peer.choked = True
        #self.CM.send_to_peer(peer, self.createMessage(Messages.CHOKE))

    def unchoke(self, peer:Peer):
        if(peer==None):
            INFOMESSAGE("Cannot unchoke Nonetype")
            return
        INFOMESSAGE(f"Unchoked {peer.peerID}")
        peer.unchoke()
        #self.CM.send_to_peer(peer, self.createMessage(Messages.UNCHOKE))

    def process_incoming_messages(self):
        """
        Runs in a separate thread or main loop to process messages.
        """
        while self.running:
            try:
                msg = self.messageQueue.get_nowait()
                self.handle_message(msg)
            except Empty:
                continue
            time.sleep(0.01)  # Prevent busy wait

    def handle_message(self, info):
        #This will handle all the different messages based on type.
        peer:Peer
        payload:bytes
        msg_type:Messages
        peer, msg_type, payload = info

        match msg_type:
            case Messages.CHOKE:
                peer.chokingUs = True
                INFOMESSAGE("Received choke message.")
                #self.dispatchQueue.put((peer, Messages.CHOKE, None))
            case Messages.UNCHOKE: #Unchoke
                if peer.chokingUs == True:
                    peer.chokingUs = False
                    #Request message here
                    INFOMESSAGE("We should request something.")
                    neededpieces = self.getNeededPieces(peer)
                    INFOMESSAGE(f"{peer.peerID}")
                    if(not(neededpieces == None)):
                        neededpiece = r.choice(neededpieces)
                        neededpiece = neededpiece.to_bytes(4, "big")
                        self.dispatchQueue.put((peer, Messages.REQUEST, neededpiece))
                else:
                # We should ignore this if they were not already choking us.    
                    INFOMESSAGE("Received unchoke message.")
                    INFOMESSAGE("We should ignore this one")
                #According to the spec, we now have to send a request message.
                #self.dispatchQueue.put((peer, Messages.UNCHOKE, None))
            case Messages.INTERESTED: #interested
                INFOMESSAGE("INTEREST MESSAGE RECEIVED")
                peer.interested = True
                #self.dispatchQueue.put((peer, Messages.INTERESTED, None))
            case Messages.NOT_INTERESTED: #Not interested
                peer.interested = False
                #self.dispatchQueue.put((peer, Messages.NOT_INTERESTED, None))
                #Should probably send choke message.
            case Messages.HAVE: #Have
                #Payload is a 4-byte piece index.
                payload = int.from_bytes(payload,"big")
                self.updateBitfield(peer, payload)
                pass
            case Messages.BITFIELD: #Bitfield
                peer.bitfield = bytearray(payload)
                self.dispatchQueue.put((peer,Messages.BITFIELD, None))
                #peer.interested = self.determineInterest(peer)
                INFOMESSAGE(f"Bitfield for Peer {peer.peerID} has been set.")
            case Messages.REQUEST: #Request
                payload = int.from_bytes(payload,"big")
                self.dispatchQueue.put((peer, Messages.PIECE,payload))
                INFOMESSAGE("Request message received.")
            case Messages.PIECE: #Piece
                INFOMESSAGE("PIECE MESSAGE RECEIVED - THIS MUST BE FIELDED.")
                #peer.gotdata()
            case Messages.HANDSHAKE:#Received handshake
                INFOMESSAGE(f"HANDSHAKE RECEIVED.")
                self.dispatchQueue.put((peer,Messages.HANDSHAKE, None))
        
    def connect_to_initial_peers(self):
        """
        The first thing a client should do is connected to available peers
        In this simple case, the available peers are the peers listed above the
        current app's peer ID in the list
        """
        for p in self.peers:
            #This will loop in order until we hit our own peerid.
            if p.peerID != self.peerid:
                self.connect_to_peer(p)
            else:
                break

    def hasCompleteFile(self):
        return self.hasCompleteFile

    def check_complete(self):
        pass

    def start(self):
        threading.Thread(target=self.CM.start).start()
        threading.Thread(target=self.process_incoming_messages).start()
        threading.Thread(target=self.managePeers).start()
        threading.Thread(target=self.unchokingLoop).start()
        threading.Thread(target=self.optimisticUnchokingLoop).start()
        self.connect_to_initial_peers()

    def stop(self):
        self.running = False
        self.CM.stop()

    def update_host(self,config_path: str, peer_id: int, new_port: int):
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
        self.dispatchQueue.put((peer, Messages.CONNECT_TO, None))

    def make_handshake(self):
        return (HANDSHAKE_HEADER + (b'\x00' * HANDSHAKE_ZERO_BITS) + self.peerid.to_bytes(4, byteorder='big'))

if __name__ == "__main__":
    PEERID = int(sys.argv[1])
    a = app(PEERID)
    a.start()
    #time.sleep(30)
    #a.stop()