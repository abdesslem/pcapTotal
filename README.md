# PcapTotal ( In process )

PcapTotal is an open source web application used to analyze PCAP using graphical representations of network traffic and detect suspcious behavoir in the communication (traffic signature and check known malicious/compromized system). The aim of PcapTotal is to make PCAP analysis and Forensics faster by providing a human-readable version of network traffic originating from a given host or network. 

### How it works !

- Register
- Submit your PCAP
- PcapTotal analyze the PCAP and return network flow information
- PcapTotal Use online service to detect Command and control service (ex: virusTotal API)

### Install and Run
```
pip install -r requirements.txt
python app.py
```

### Main Components

- Packet Parser : This module is used to parse the packets from the files and return the list of packets
- Stream Parser : This module is used to parse the sessions from the files and return the list of sessions
- Accessor : This module is used to store the data in mongodb database
- Scanner : This module is used to scan the pcap for suspicouis IP or behavoirs
- Viewer : This module is used to visualize the network traffic 
- API : The Api allow developper to submit file and get result automatically

### API

PcapTotal implements a flexible API allow used to programmatically submit pcap files and get the result.

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/abdesslem/pcaptotal/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

