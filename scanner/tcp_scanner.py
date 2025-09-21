from scapy.all import IP, TCP, sr1   # Importa da Scapy: la classe IP, il protocollo TCP e la funzione sr1 per inviare pacchetti e ricevere una sola risposta

def tcp_scan(host, ports):   # Definisce la funzione tcp_scan che riceve un host e una lista di porte
    """
    Funzione per effettuare una scansione delle porte TCP su un host specifico usando Scapy.

    Args:
        host (str): L'indirizzo IP o il nome host da scansionare.
        ports (list): Lista di porte da scansionare.

    Returns:
        list: Lista di porte TCP aperte.
    """
    open_ports = []   # Lista vuota che conterrà le porte TCP trovate aperte

    for port in ports:   # Itera su ciascuna porta da scansionare
        pkt = IP(dst=host) / TCP(dport=port, flags='S')   # Crea un pacchetto IP+TCP con flag SYN (tentativo di apertura connessione)
        response = sr1(pkt, timeout=1, verbose=False)     # Invia il pacchetto e attende una risposta per massimo 1 secondo

        if response is not None:   # Se è arrivata una risposta
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:   # Se la risposta è TCP con flag SYN-ACK (0x12)
                open_ports.append(port)   # La porta è considerata aperta e viene aggiunta alla lista
                sr1(IP(dst=host) / TCP(dport=port, flags='R'), timeout=1, verbose=False)   # Invia un pacchetto RST per chiudere la connessione

    return open_ports   # Restituisce la lista delle porte TCP aperte