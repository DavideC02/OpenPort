import socket   # Importa il modulo socket per creare connessioni di rete TCP/IP

def service_analysis(host, port):   # Definisce la funzione per analizzare un servizio in esecuzione su una porta
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:   # Crea un socket TCP/IPv4 e lo chiude automaticamente a fine blocco
            s.settimeout(3)                     # Imposta un timeout di 3 secondi per le operazioni sul socket
            s.connect((host, port))             # Tenta la connessione all'host e porta specificati
            s.send(b'HEAD / HTTP/1.1\r\n\r\n')  # Invia una richiesta HTTP HEAD minimale al servizio
            response = s.recv(100).decode()     # Riceve fino a 100 byte di risposta e li decodifica in stringa
            return response.splitlines()[0]     # Restituisce la prima riga della risposta (es. "HTTP/1.1 200 OK")
    except socket.timeout:                      # Se il servizio non risponde entro il timeout
        return "Timeout del servizio"
    except ConnectionRefusedError:              # Se la connessione viene rifiutata (porta chiusa)
        return "Connessione rifiutata"
    except Exception as e:                      # Per qualsiasi altro errore
        return f"Errore: {e}"