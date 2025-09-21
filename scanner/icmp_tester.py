from scapy.all import IP, ICMP, sr1   # Importa da Scapy: classe IP, protocollo ICMP e funzione sr1 per inviare pacchetti e ricevere una risposta

def icmp_ping(host):   # Definisce la funzione che invia un ping ICMP a un host
    pkt = IP(dst=host) / ICMP()               # Crea un pacchetto IP con destinazione l'host, contenente un messaggio ICMP Echo Request (ping)
    response = sr1(pkt, timeout=1, verbose=False)   # Invia il pacchetto e attende una risposta per massimo 1 secondo, senza output dettagliato
    return response is not None               # Restituisce True se è arrivata una risposta, False altrimenti