import socket
import struct
from socket import inet_ntoa

class Protocols:
    DHCP_HEADER = struct.Struct("!4BI2H4s4s4s4s16s64s128sI")

    @staticmethod
    def decode_dhcp(message: bytes) -> dict:
        dhcp_header = Protocols.DHCP_HEADER.unpack_from(message)
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, bootf = dhcp_header

        result = {
            "op": op,
            "htype": htype,
            "hlen": hlen,
            "hops": hops,
            "xid": xid,
            "secs": secs,
            "flags": flags,
            "ciaddr": inet_ntoa(ciaddr),
            "yiaddr": inet_ntoa(yiaddr),
            "siaddr": inet_ntoa(siaddr),
            "giaddr": inet_ntoa(giaddr),
            "chaddr": ':'.join(f"{i:02x}" for i in chaddr[:6]),
            "sname": sname.decode('utf-8').rstrip('\x00'),
            "bootf": bootf.decode('utf-8').rstrip('\x00')
        }

        options = Protocols.parse_dhcp_options(message, Protocols.DHCP_HEADER.size)
        result.update(options)

        return result

    @staticmethod
    def parse_dhcp_options(message: bytes, offset: int) -> dict:
        options = {}
        while offset < len(message):
            option, length = struct.unpack_from("!BB", message, offset)
            offset += 2
            if option == 0:
                break
            data = struct.unpack_from(f"!{length}s", message, offset)[0]
            offset += length
            options[option] = data
        return options

def main():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except OSError as e:
        print(f"Error creating socket: {e}")
        return
    
    while True:
        message, _ = sock.recvfrom(2048)
        dhcp_message = Protocols.decode_dhcp(message)
        print("Received DHCP message:")
        print(dhcp_message)

if __name__ == "__main__":
    main()