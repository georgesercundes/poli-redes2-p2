from scapy.all import IP, TCP, sr1, ICMP, RandShort

# Função para realizar o Port Scan
def portScan(target, port):

    # Valor da flag de resposta para porta aberta
    SYNACK = 18

    # Valor da flag de resposta para porta fechada
    RSTACK = 20

    # Definir uma porta de envio aleatória para o pacote TCP
    sport = RandShort()

    # Pacote TCP com a flag SYN a ser enviada para o endereço IP de destino
    syn = IP(dst=target) / TCP (sport=sport, dport=port, flags ='S')

    # Enviar o pacote e armazenar a resposta na variável packet
    packet = sr1(syn, timeout=2, retry=1, verbose=0)
    
    # Se a resposta não for vazia
    if packet != None:

        # Para uma resposta TCP verificar a flag de resposta e definir status da porta
        if packet.haslayer(TCP):
            if packet[TCP].flags == SYNACK:
                print ('Porta {} - Status: Aberta'.format(port))
            elif packet[TCP].flags == RSTACK:
                print ('Porta {} - Status: Fechada'.format(port))
            else:
                 print('Porta {} - Status: Filtrada'.format(port))

        # Para uma resposta ICMP definir o status da porta como 'filtrada'
        elif packet.haslayer(ICMP):
            print('Porta {} - Status: Filtrada'.format(port))

        # Para uma resposta que não seja nem TCP nem ICMP definir os status porta como 'desconhecido'
        else:
            print('Porta {} - Status: Desconhecido'.format(port))

    # Se a resposta for vazia definir o status da porta como 'sem resposta'
    else:
        print('Porta {} - Status: Sem Resposta'.format(port))      
        
def run ():

  # Receber do usuário os valores mínimo e máximo do intervalo das portas e verificar se é válido
    while True:
        min_port = input('Digite o valor mínimo do intervalo das portas: ')
        max_port = input('Digite o valor máximo do intervalo das portas: ')

        if int(min_port) >= 0 and int(max_port) >= 0 and int (max_port) >= int(min_port):  
            break
        else:
            print('Intervalo de portas inválido')
  
    # Receber do usuário o IP de destino e verificar se o host está online
    while True:
        target = input('Digite o endereço IP: ')
        try:
            icmp = IP(dst=target)/ICMP()
            ping = sr1 (icmp, verbose=0)
            print('Endereço IP de Destino OK, Analisando portas do endereço {}...'.format(target))
            break
        except Exception:
            print('Endereço IP inalcançável')          

    ports = range(int(min_port), int(max_port)+ 1)
    for port in ports:
        portScan(target, port)

    input('Digite Enter para sair')
        
if __name__ == '__main__':
    run()       