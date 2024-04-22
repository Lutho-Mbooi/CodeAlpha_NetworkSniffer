The IPHeader class is responsible for parsing the IP header of a network packet and extracting relevant information such as the version,
header length, time to live (TTL), protocol, source IP address, destination IP address, and the data payload.

The IPHeader class has the following fields:

version: An integer representing the IP version (4 or 6).
header_length: An integer representing the length of the IP header in bytes.
ttl: An integer representing the time to live value of the packet.
protocol: An integer representing the protocol number (e.g., 6 for TCP, 17 for UDP).
source_ip: A string representing the source IP address.
destination_ip: A string representing the destination IP address.
data: A bytes object representing the data payload of the packet.

Functions: 

The conn function creates a raw socket and configures it to receive all IP packets.
It then enables promiscuous mode on the socket and returns it.


The main function is responsible for starting a packet sniffer that captures network packets and logs them to a pcap file.
It uses the conn function to create a socket for receiving packets. The function continuously receives packets, 
extracts the IP header information, and prints the source and destination IP addresses if the packet is TCP or UDP. 
It then logs the packet to a pcap file along with a timestamp and packet length.

Technology Used: 

Python
