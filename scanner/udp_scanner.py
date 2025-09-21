from scapy.all import IP, UDP, sr1   # Importa da Scapy: la classe IP, il protocollo UDP e la funzione sr1 per inviare pacchetti e ricevere una sola risposta

def udp_scan(host, ports):   # Definisce la funzione udp_scan che riceve un host e una lista di porte
    """
    Funzione per effettuare una scansione delle porte UDP su un host specifico usando Scapy.

    Args:
        host (str): L'indirizzo IP o il nome host da scansionare.
        ports (list): Lista di porte da scansionare.

    Returns:
        list: Lista di porte UDP aperte.
    """
    open_ports = []   # Inizializza una lista vuota per salvare le porte aperte

    for port in ports:   # Itera su ciascuna porta della lista fornita
        pkt = IP(dst=host) / UDP(dport=port)   # Crea un pacchetto IP destinato all'host con segmento UDP verso la porta corrente
        response = sr1(pkt, timeout=1, verbose=False)   # Invia il pacchetto e attende al massimo 1 secondo per una risposta (senza output verbose)

        if response is None:   # Se non riceve alcuna risposta
            open_ports.append(port)   # Considera la porta come "aperta o filtrata" e la aggiunge alla lista
        elif response.haslayer(UDP):   # Se la risposta contiene un livello UDP
            open_ports.append(port)    # La porta è considerata aperta e viene aggiunta alla lista

    return open_ports   # Restituisce la lista delle porte aperte trovate