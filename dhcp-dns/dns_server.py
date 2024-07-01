import socket

class DNSServer:
    def __init__(self, ip='0.0.0.0', port=53):
        self.ip = ip
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        self.redirects = {
            b"example.com": "93.184.216.34",  # Exemplo: redireciona example.com para um IP
        }

    def handle_query(self, data, addr):
        transaction_id = data[:2]
        flags = b'\x81\x80'
        questions = data[4:6]
        answer_rrs = b'\x00\x01'
        authority_rrs = b'\x00\x00'
        additional_rrs = b'\x00\x00'
        query_name = data[12:-4]
        query_type = data[-4:-2]
        query_class = data[-2:]

        response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + data[12:]
        
        domain_name = b".".join(query_name.split(b'\x03'))  # exemplo.com
        if domain_name in self.redirects:
            ip = socket.inet_aton(self.redirects[domain_name])
        else:
            ip = socket.inet_aton("1.1.1.1")  # Redireciona para um IP padrão
        
        response += b'\xc0\x0c' + query_type + query_class + b'\x00\x00\x00\x3c' + b'\x00\x04' + ip
        
        self.socket.sendto(response, addr)
        print(f"Responded to {addr} with {socket.inet_ntoa(ip)} for {domain_name.decode('utf-8')}")

    def run(self):
        print("DNS Server is running...")
        while True:
            data, addr = self.socket.recvfrom(512)
            self.handle_query(data, addr)

if __name__ == "__main__":
    server = DNSServer()
    server.run()
