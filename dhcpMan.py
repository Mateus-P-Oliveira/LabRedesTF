import socket
import struct
from typing import Dict, List
from socket import inet_ntoa

class Protocols:
    DHCP_HEADER = struct.Struct("!4BI2H4s4s4s4s16s64s128sI")

    @staticmethod
    def decode_dhcp(message: bytes, display: List, offset: int) -> Dict:
        '''Decode DHCP packet
        Args:
            message (bytes): The received data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 offset
        Returns:
            result (Dict): The decode result
        '''
        try:
            dhcp_header = Protocols.DHCP_HEADER.unpack_from(message, offset)
        except struct.error:
            print("Erro ao desempacotar o cabeçalho DHCP. O tamanho do pacote pode estar incorreto.")
            return {}

        # Corrigido: Desempacotar apenas os campos necessários
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = dhcp_header

        result = {
            "op": op,
            "htype": htype,
            "hlen": hlen,
            "hops": hops,
            "xid": hex(xid),
            "secs": secs,
            "flags": flags,
            "ciaddr": inet_ntoa(ciaddr),
            "yiaddr": inet_ntoa(yiaddr),
            "siaddr": inet_ntoa(siaddr),
            "giaddr": inet_ntoa(giaddr),
            "chaddr": ':'.join(f"{i:02x}" for i in chaddr[:6]),
        }

        options = Protocols.parse_dhcp_options(message, offset + Protocols.DHCP_HEADER.size)
        result.update(options)

        if "DHCP" in display:
            print("Mensagem DHCP recebida:")
            print(result)

        return result

    @staticmethod
    def parse_dhcp_options(message: bytes, offset: int) -> Dict:
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
        print(f"Erro ao criar o socket: {e}")
        return
    
    while True:
        message, _ = sock.recvfrom(2048)
        dhcp_message = Protocols.decode_dhcp(message, display=["DHCP"], offset=0)
        print("Mensagem DHCP recebida:")
        print(dhcp_message)

if __name__ == "__main__":
    main()

