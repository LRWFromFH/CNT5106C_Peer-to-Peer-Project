# CNT5106C_Peer-to-Peer-Project

Run peerProcess.py in the root directory and make sure to only use peer IDs 2324 (First) and 2325 (second).

For the midpoint submission, the code will only run for about 30 seconds. During that time, 2325 will reach out to 2324 using the updated IP/port in the PeerInfo.cfg file.

At the moment, there is a bug where it will continuously connect, send the handshake and bitfield and validate the received bitfield.

This is a bug that we are working on.
