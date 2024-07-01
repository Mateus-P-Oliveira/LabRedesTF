import socket
import struct
import time
import os
import subprocess

def create_dhcp_client_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return sock

def send_dhcp_discover(sock):
    transaction_id = b'\x39\x03\xF3\x26'  # Exemplo de ID de transação
    mac_address = b'\x00\x0c\x29\x3e\x1c\x7e'  # MAC address de exemplo
    discover_packet = b''
    discover_packet += b'\x01'  # Op (1 = Boot Request)
    discover_packet += b'\x01'  # Htype (Ethernet)
    discover_packet += b'\x06'  # Hlen (6 bytes)
    discover_packet += b'\x00'  # Hops
    discover_packet += transaction_id  # Xid
    discover_packet += b'\x00\x00'  # Secs
    discover_packet += b'\x80\x00'  # Flags (Broadcast)
    discover_packet += b'\x00\x00\x00\x00'  # Ciaddr
    discover_packet += b'\x00\x00\x00\x00'  # Yiaddr
    discover_packet += b'\x00\x00\x00\x00'  # Siaddr
    discover_packet += b'\x00\x00\x00\x00'  # Giaddr
    discover_packet += mac_address  # Chaddr
    discover_packet += b'\x00' * 10  # Chaddr padding
    discover_packet += b'\x00' * 192  # Bootp legacy padding
    discover_packet += b'\x63\x82\x53\x63'  # Magic cookie
    discover_packet += b'\x35\x01\x01'  # DHCP Message Type (Discover)
    discover_packet += b'\x37\x03\x03\x01\x06'  # Parameter Request List
    discover_packet += b'\xff'  # End Option

    sock.sendto(discover_packet, ('<broadcast>', 67))
    print("DHCP Discover enviado.")

def send_dhcp_request(sock, transaction_id, requested_ip, server_ip):
    mac_address = b'\x00\x0c\x29\x3e\x1c\x7e'  # MAC address de exemplo
    request_packet = b''
    request_packet += b'\x01'  # Op (1 = Boot Request)
    request_packet += b'\x01'  # Htype (Ethernet)
    request_packet += b'\x06'  # Hlen (6 bytes)
    request_packet += b'\x00'  # Hops
    request_packet += transaction_id  # Xid
    request_packet += b'\x00\x00'  # Secs
    request_packet += b'\x80\x00'  # Flags (Broadcast)
    request_packet += b'\x00\x00\x00\x00'  # Ciaddr
    request_packet += b'\x00\x00\x00\x00'  # Yiaddr
    request_packet += b'\x00\x00\x00\x00'  # Siaddr
    request_packet += b'\x00\x00\x00\x00'  # Giaddr
    request_packet += mac_address  # Chaddr
    request_packet += b'\x00' * 10  # Chaddr padding
    request_packet += b'\x00' * 192  # Bootp legacy padding
    request_packet += b'\x63\x82\x53\x63'  # Magic cookie
    request_packet += b'\x35\x01\x03'  # DHCP Message Type (Request)
    request_packet += b'\x32\x04' + requested_ip  # Requested IP Address
    request_packet += b'\x36\x04' + server_ip  # DHCP Server Identifier
    request_packet += b'\xff'  # End Option

    sock.sendto(request_packet, ('<broadcast>', 67))
    print("DHCP Request enviado.")
    

def apply_dns_configuration(dns_ip):
    resolv_conf_path = '/etc/resolv.conf'
    with open(resolv_conf_path, 'w') as resolv_conf:
        resolv_conf.write(f"nameserver {dns_ip}\n")
    print(f"Configuração DNS aplicada: {dns_ip}")

def perform_dns_query(domain, dns_ip):
    result = subprocess.run(['nslookup', domain, dns_ip], capture_output=True, text=True)
    print(result.stdout)

def main():
    client_socket = create_dhcp_client_socket()
    send_dhcp_discover(client_socket)

    # Aguardar a resposta DHCP Offer do servidor
    time.sleep(5)  # Esperar 5 segundos para receber a oferta e simular um tempo de processamento

    # Exemplo de transação e IPs para teste. No cenário real, esses valores seriam extraídos da resposta DHCP Offer
    transaction_id = b'\x39\x03\xF3\x26'  # Mesmo ID de transação usado no Discover
    requested_ip = socket.inet_aton('192.168.1.100')  # IP oferecido pelo servidor DHCP
    server_ip = socket.inet_aton('192.168.1.1')  # IP do servidor DHCP

    send_dhcp_request(client_socket, transaction_id, requested_ip, server_ip)
    
    apply_dns_configuration('192.168.1.1')

if __name__ == "__main__":
    main()
