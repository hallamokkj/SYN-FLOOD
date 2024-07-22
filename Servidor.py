from scapy.all import *
import random

# Função para enviar um pacote SYN
def send_syn(target_ip, target_port):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, sport=random.randint(1024, 65535), flags='S', seq=random.randint(1, 65535))
    packet = ip/tcp
    response = sr1(packet, timeout=2)  # Aumentar o timeout para esperar mais pela resposta
    return response

# Função para enviar um pacote ACK
def send_ack(target_ip, target_port, seq, ack):
    ip = IP(dst=target_ip)
    tcp = TCP(dport=target_port, sport=random.randint(1024, 65535), flags='A', seq=ack, ack=seq+1)
    packet = ip/tcp
    send(packet)

def perform_handshake(target_ip, target_port):
    print(f"Enviando pacote SYN para {target_ip}:{target_port}")
    
    # Envia SYN e espera o SYN-ACK
    syn_response = send_syn(target_ip, target_port)
    
    if syn_response:
        # Extrai números de sequência e de confirmação
        syn_ack_seq = syn_response[TCP].seq
        syn_ack_ack = syn_response[TCP].ack
        
        print(f"Recebido SYN-ACK de {target_ip}:{target_port}")
        print(f"Número de sequência do SYN-ACK: {syn_ack_seq}")
        print(f"Número de confirmação do SYN-ACK: {syn_ack_ack}")

        # Envia ACK para completar o handshake
        print(f"Enviando pacote ACK para {target_ip}:{target_port}")
        send_ack(target_ip, target_port, syn_ack_seq, syn_ack_ack)
        print("Handshake completo.")
    else:
        print("Não foi possível receber resposta SYN-ACK.")

if __name__ == "__main__":
    # Solicita o IP e a porta alvo do usuário
    target_ip = input("Digite o IP alvo: ")
    target_port = int(input("Digite a porta alvo: "))
    
    perform_handshake(target_ip, target_port)
