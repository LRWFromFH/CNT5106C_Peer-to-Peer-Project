# CNT5106C_Peer-to-Peer-Project

Run with python peerProcess.py [peer id]
You will have to provide Common.cfg and PeerInfo.cfg as outlined in the submission guidelines.

File structure:
    - CNT5106C_PEER-TO-PEER-PROJECT
        - Configs
            - [Peer id]
                [File for transmission]
            Common.cfg
            PeerInfo.cfg
        - peerProcess.py

Division of work: (Not indicative of task difficulty)
    Alexander Martin:
        Connection Manager Class
        Initial configuration/connections
        Message queues
        Main message logic
        Bitfield generation/update
        Stop conditions
        Interest determination

    Alexander Lapsley:
        File IO
        Peer Choke/Unchoke
        logging
        Bitfield logic for needed pieces (Sending/receiving/saving)

Link to video:
https://uflorida-my.sharepoint.com/:v:/g/personal/alexander_martin_ufl_edu/IQAlZRGurMsgSJpdi1iYk-7fAeeaATdouLkLdbMxmfeFkh0?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJPbmVEcml2ZUZvckJ1c2luZXNzIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXciLCJyZWZlcnJhbFZpZXciOiJNeUZpbGVzTGlua0NvcHkifX0&e=Tz5cwi
