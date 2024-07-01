from scapy.all import *

def send_dhcp_discover():
    # Configuração do endereço MAC do cliente
    client_mac = "00:11:22:33:44:55"
    
    # Cria o pacote DHCP DISCOVER
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac, type=0x0800) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=[mac2str(client_mac)]) /
        DHCP(options=[("message-type", "discover"), "end"])
    )
    
    # Envia o pacote DHCP DISCOVER
    sendp(dhcp_discover, iface="eth0", verbose=True)

if __name__ == "__main__":
    send_dhcp_discover()
