import ipaddress   # Importa il modulo per gestire indirizzi e range IP

from .icmp_tester import icmp_ping   # Importa la funzione per fare ping ICMP dal modulo icmp_tester
from .tcp_scanner import tcp_scan    # Importa la funzione per eseguire la scansione TCP dal modulo tcp_scanner
import time                          # Importa il modulo time per inserire pause tra le scansioni

# Funzione per la scansione di un intervallo di indirizzi IP
def ip_range_scan(start_ip, end_ip, ports):   # Definisce la funzione che riceve IP iniziale, IP finale e lista di porte
    start = ipaddress.IPv4Address(start_ip)   # Converte l'IP iniziale in oggetto IPv4Address
    end = ipaddress.IPv4Address(end_ip)       # Converte l'IP finale in oggetto IPv4Address
    open_hosts = {}                           # Dizionario che conterrà host attivi e relative porte aperte

    for ip in range(int(start), int(end) + 1):   # Itera su tutti gli IP compresi nell'intervallo
        ip_str = str(ipaddress.IPv4Address(ip))  # Converte l'indirizzo numerico in stringa
        try:
            if icmp_ping(ip_str):   # Se l'host risponde al ping ICMP (è attivo)
                open_ports = tcp_scan(ip_str, ports)   # Esegue la scansione TCP sulle porte specificate
                if open_ports:                         # Se sono state trovate porte aperte
                    open_hosts[ip_str] = open_ports    # Salva l'host con la lista di porte aperte nel dizionario
            time.sleep(0.1)   # Attende 0.1 secondi per non sovraccaricare la rete
        except Exception as e:   # Gestione di eventuali errori durante la scansione
            print(f"Errore durante la scansione dell'IP {ip_str}: {str(e)}")   # Stampa l'errore a console
    return open_hosts   # Restituisce il dizionario con gli host attivi e le rispettive porte aperte