import socket
import struct
import datetime

class IPHeader:
    def __init__(self, raw_data):
        
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl, self.protocol, src, self.dst = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
        self.source_ip = socket.inet_ntoa(src)
        self.destination_ip = socket.inet_ntoa(self.dst)
        self.data = raw_data[self.header_length:]

def conn():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind(("0.0.0.0", 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode
    return sock

def main():
    sniffer = conn()
    print("Sniffer Started...")
    try:
        while True:
            raw_packet, _ = sniffer.recvfrom(65535)
            ip_header = IPHeader(raw_packet)
            if ip_header.protocol == socket.IPPROTO_TCP:
                print(f"TCP Packet - Source: {ip_header.source_ip}, Destination: {ip_header.destination_ip}")
            elif ip_header.protocol == socket.IPPROTO_UDP:
                print(f"UDP Packet - Source: {ip_header.source_ip}, Destination: {ip_header.destination_ip}")
            # Log packets to a pcap file
            with open("packet_log.pcap", "ab") as f:
                timestamp = datetime.datetime.now().timestamp()
                f.write(struct.pack("!I", int(timestamp)))  # Timestamp seconds
                f.write(struct.pack("!I", 0))  # Timestamp microseconds
                f.write(struct.pack("!I", len(raw_packet)))  # Captured length
                f.write(struct.pack("!I", len(raw_packet)))  # Original length
                f.write(raw_packet)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # Disable promiscuous mode
        sniffer.close()

if __name__ == "__main__":
    main()
