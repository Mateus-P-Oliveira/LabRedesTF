import socket
import struct
import random

# Constantes DHCP
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# Dados de configuração DHCP
subnet = "192.168.1.0"
netmask = "255.255.255.0"
router = "192.168.1.1"
dns_server = "8.8.8.8"
lease_time = 86400  # Tempo de concessão do endereço IP em segundos (1 dia)

def generate_transaction_id():
    return random.randint(1, 900000000)

def send_dhcp_offer(client_mac, client_ip, transaction_id):
    dhcp_offer = create_dhcp_packet(client_mac, client_ip, transaction_id, DHCP_OFFER)
    send_dhcp_packet(dhcp_offer)

def send_dhcp_ack(client_mac, client_ip, transaction_id):
    dhcp_ack = create_dhcp_packet(client_mac, client_ip, transaction_id, DHCP_ACK)
    send_dhcp_packet(dhcp_ack)

def create_dhcp_packet(client_mac, client_ip, transaction_id, dhcp_type):
    # Monta o pacote DHCP com base no tipo especificado (Offer ou Acknowledgement)
    dhcp_options = [
        (53, struct.pack('B', dhcp_type)),  # Type (DHCP Offer ou DHCP Acknowledgement)
        (54, socket.inet_aton(router)),    # Server Identifier (endereço IP do servidor DHCP)
        (51, struct.pack('>I', lease_time)),  # Lease Time (tempo de concessão em segundos)
        (1, socket.inet_aton(subnet)),     # Subnet Mask
        (3, socket.inet_aton(router)),     # Router (gateway padrão)
        (6, socket.inet_aton(dns_server)), # DNS Server
        (255, b'')                         # End
    ]

    # Monta o pacote DHCP
    dhcp_packet = struct.pack('!BBH', 0x02, 0x01, 0x08)  # BOOTP op, htype, hlen, hops
    dhcp_packet += struct.pack('!I', transaction_id)    # Transaction ID
    dhcp_packet += struct.pack('!H', 0)                 # Seconds
    dhcp_packet += struct.pack('!H', 0)                 # Flags
    dhcp_packet += socket.inet_aton('0.0.0.0')          # Client IP address
    dhcp_packet += socket.inet_aton(client_ip)          # Your (client) IP address
    dhcp_packet += socket.inet_aton('0.0.0.0')          # Next server IP address
    dhcp_packet += socket.inet_aton('0.0.0.0')          # Relay agent IP address
    dhcp_packet += struct.pack('!6s', client_mac)       # Client MAC address
    dhcp_packet += b'\x00' * 202                        # Padding
    dhcp_packet += b'\x63\x82\x53\x63'                 # Magic cookie

    for option, value in dhcp_options:
        dhcp_packet += struct.pack('!BB', option, len(value)) + value

    return dhcp_packet

def send_dhcp_packet(packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(('0.0.0.0', DHCP_SERVER_PORT))
    s.sendto(packet, ('<broadcast>', DHCP_CLIENT_PORT))
    s.close()

def handle_dhcp_packet(packet):
    op = struct.unpack('!B', packet[0:1])[0]
    htype = struct.unpack('!B', packet[1:2])[0]
    hlen = struct.unpack('!B', packet[2:3])[0]
    hops = struct.unpack('!B', packet[3:4])[0]
    xid = struct.unpack('!I', packet[4:8])[0]
    secs = struct.unpack('!H', packet[8:10])[0]
    flags = struct.unpack('!H', packet[10:12])[0]
    ciaddr = socket.inet_ntoa(packet[12:16])
    yiaddr = socket.inet_ntoa(packet[16:20])
    siaddr = socket.inet_ntoa(packet[20:24])
    giaddr = socket.inet_ntoa(packet[24:28])
    chaddr = ':'.join('%02x' % b for b in struct.unpack('!6B', packet[28:34]))
    magic_cookie = packet[236:240]
    print("recebi")
    if magic_cookie != b'\x63\x82\x53\x63':
        return

    options = packet[240:]

    option_idx = 0
    while option_idx < len(options):
        option_type = struct.unpack('!B', options[option_idx:option_idx+1])[0]
        if option_type == 255:
            break
        option_length = struct.unpack('!B', options[option_idx+1:option_idx+2])[0]
        option_value = options[option_idx+2:option_idx+2+option_length]
        option_idx += 2 + option_length

        if option_type == 53:  # DHCP Message Type
            message_type = struct.unpack('!B', option_value)[0]
            if message_type == DHCP_DISCOVER:
                print(f"Received DHCP Discover from {chaddr}")
                send_dhcp_offer(chaddr, yiaddr, xid)
            elif message_type == DHCP_REQUEST:
                print(f"Received DHCP Request from {chaddr}")
                send_dhcp_ack(chaddr, yiaddr, xid)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.bind(('0.0.0.0', DHCP_SERVER_PORT))
    print("Socket [baseDHCP]", s)


    while True:
        packet, address = s.recvfrom(4096)
        handle_dhcp_packet(packet)

if __name__ == "__main__":
    main()
