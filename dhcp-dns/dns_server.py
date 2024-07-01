import socket

def start_dns_server():
    dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_socket.bind(('0.0.0.0', 53))
    dns_mapping = {
        b'www.exemplo.com': '192.168.1.101',
        b'www.outrosite.com': '192.168.1.102'
    }
    while True:
        query, addr = dns_socket.recvfrom(512)
        domain = extract_domain_from_query(query)
        if domain in dns_mapping:
            response = build_dns_response(query, dns_mapping[domain])
            dns_socket.sendto(response, addr)
            print(f"Consulta DNS para {domain} respondida com {dns_mapping[domain]}")

def extract_domain_from_query(query):
    domain = b''
    i = 12
    while query[i] != 0:
        length = query[i]
        domain += query[i+1:i+1+length] + b'.'
        i += length + 1
    return domain[:-1]

def build_dns_response(query, ip):
    transaction_id = query[:2]
    flags = b'\x81\x80'
    questions = query[4:6]
    answer_rrs = b'\x00\x01'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query[12:]
    response += b'\xc0\x0c'  # Nome (ponto de referência para o nome do domínio)
    response += b'\x00\x01'  # Tipo (A)
    response += b'\x00\x01'  # Classe (IN)
    response += b'\x00\x00\x00\x3c'  # TTL (60 segundos)
    response += b'\x00\x04'  # Comprimento dos dados
    response += socket.inet_aton(ip)  # Endereço IP
    return response

def main():
    threading.Thread(target=dhcp_server_main).start()
    threading.Thread(target=start_dns_server).start()

def dhcp_server_main():
    dhcp_socket = create_dhcp_socket()
    receive_dhcp_message(dhcp_socket)

if __name__ == "__main__":
    main()
