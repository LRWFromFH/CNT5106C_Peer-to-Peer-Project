from dataclasses import dataclass

@dataclass
class Peer:
    peerID: int
    hostname: str
    port: int
    hasFileFlag: bool
    active: bool = False

    def __post_init__(self):
        self.peerID = int(self.peerID)
        self.port = int(self.port)
        self.hasFileFlag = bool(int(self.hasFileFlag))

p = Peer(1001, "localhost", 6000, 0)
print(id(p))  # memory address

def f(peer):
    print(id(peer))
    peer.active = True

f(p)
print(p.active)  # True
