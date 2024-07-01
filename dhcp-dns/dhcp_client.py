import socket
import struct
import random

def send_dhcp_discover():
    transaction_id = random.randint(0, 0xFFFFFFFF)
    mac_address = b'\x00\x0c\x29\x3e\x9e\xb1'
    
    dhcp_discover = struct.pack(
        '!4B I 2H 4s 4s 4s 4s 16s 64s 128s',
        1, 1, 6, 0,  # op, htype, hlen, hops
        transaction_id,  # xid
        0, 0,  # secs, flags
        b'\x00\x00\x00\x00',  # ciaddr
        b'\x00\x00\x00\x00',  # yiaddr
        b'\x00\x00\x00\x00',  # siaddr
        b'\x00\x00\x00\x00',  # giaddr
        mac_address,  # chaddr
        b'\x00' * 64,  # sname
        b'\x00' * 128  # file
    ) + b'\x63\x82\x53\x63'  # Magic cookie
    
    dhcp_discover += struct.pack('!3B', 53, 1, 1)  # DHCP Discover
    dhcp_discover += b'\xff'  # End option
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('0.0.0.0', 68))
    
    sock.sendto(dhcp_discover, ('<broadcast>', 67))
    print("DHCP Discover sent")

    while True:
        data, _ = sock.recvfrom(1024)
        print(f"Received packet: {data}")

if __name__ == "__main__":
    send_dhcp_discover()
