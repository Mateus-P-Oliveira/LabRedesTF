import socket
import struct

def send_dhcp_message():
    # Configurações do servidor DHCP
    server_ip = "192.168.1.1"
    client_mac = b"\x00\x11\x22\x33\x44\x55"  # Endereço MAC do cliente
    transaction_id = 123456  # ID da transação DHCP

    # Crie o pacote DHCP
    dhcp_packet = struct.pack("!4BI2H4s4s4s4s16s64s128sI", 1, 1, 6, 0, transaction_id, 0, 0, b"\x00" * 4, b"\x00" * 4,
                              b"\x00" * 4, b"\x00" * 4, client_mac, b"", b"", 0)

    # Crie um socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Envie a mensagem DHCP para o servidor
    sock.sendto(dhcp_packet, (server_ip, 67))

    print("Mensagem DHCP enviada com sucesso!")

if __name__ == "__main__":
    send_dhcp_message()
