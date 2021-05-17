from scapy.all import ARP, Ether, srp
import socket

# Função para capturar o IP externo do host
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

def run():
    input('Pressione Enter para executar o ARP Scan')

    # Definir o destino como todos os endereços ips na sub-rede 255.255.255.0
    target_ip = get_ip() + '/24'

    # Definir o alvo dos pacotes ARP com os endereços IP acima
    arp = ARP(pdst=target_ip)

    # Definir Endereço MAC de Destino como endereço broadcast
    ether = Ether (dst ='ff:ff:ff:ff:ff:ff')

    # Pacote ARP
    packet = ether/arp

    # Enviar o pacote e armazenar resposta na variável ans
    ans, unans = srp (packet, timeout=3, retry=1, verbose=0)

    clients = []

    # Inserir os endereços MAC e IP, recebidos nas mensagens de resposta dos dispositivos, no array clients
    for sent, received in ans:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    print ('Dispositivos Conectados na Rede Local:')

    # Impressão formatada dos endereços MAC e IP que estão conectados na rede local
    print('{:<20} {}'.format('IP ADDRESS', 'MAC ADDRESS'))
    for client in clients:
        print('{:<20} {}'.format(client['ip'], client['mac']))
    input('Pressione Enter para sair')

if __name__ == '__main__':
    run()       