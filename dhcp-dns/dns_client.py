import socket

def send_dns_query(domain):
    transaction_id = b'\x12\x34'  # Identificação da transação
    flags = b'\x01\x00'  # Flags: consulta padrão
    questions = b'\x00\x01'  # Número de questões
    answer_rrs = b'\x00\x00'  # Número de respostas
    authority_rrs = b'\x00\x00'  # Número de autoridades
    additional_rrs = b'\x00\x00'  # Número de registros adicionais

    query = b''
    for part in domain.split('.'):
        query += bytes([len(part)]) + part.encode()
    query += b'\x00'  # Fim do nome do domínio

    query_type = b'\x00\x01'  # Tipo de consulta (A)
    query_class = b'\x00\x01'  # Classe de consulta (IN)

    dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query + query_type + query_class

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(dns_query, ('127.0.0.1', 53))  # Enviar para o servidor DNS local
    print(f"DNS query sent for {domain}")

    response, _ = sock.recvfrom(1024)
    print(f"Received response: {response}")

if __name__ == "__main__":
    send_dns_query('example.com')
