# 🔎 Scansphere

Scansphere è uno strumento semplice ma efficace per esplorare una rete: individua quali dispositivi rispondono, quali porte sono aperte e fornisce una prima indicazione sul servizio in ascolto. È stato pensato con un approccio didattico-pratico: utile per chi vuole imparare come funzionano ICMP, TCP SYN scan e le pipeline base delle scansioni UDP, senza rinunciare a una comoda interfaccia grafica (PyQt5).

---

## 📌 Cosa fa Scansphere (spiegazione dettagliata)

Scansphere mette insieme più moduli che lavorano in modo coordinato per mappare rapidamente uno spazio di indirizzi IP e le porte esposte. Di seguito trovi una spiegazione passo-passo, in linguaggio discorsivo e pratico, di **cosa** succede quando lanci una scansione.

1. **Verifica raggiungibilità (Ping ICMP)**  
   Invia pacchetti ICMP Echo Request (ping) per capire se un host risponde. Se arriva un Echo Reply, l’host viene segnato come attivo.  
   > Attenzione: alcuni dispositivi possono bloccare ICMP, quindi un mancato ping non sempre significa che l’host è spento.

2. **Scansione porte TCP (SYN scan)**  
   Invia pacchetti SYN sulle porte indicate:  
   - **SYN-ACK** → porta aperta (lo scanner invia subito RST per non stabilire la connessione).  
   - **RST** → porta chiusa.  
   - Nessuna risposta → porta filtrata.  
   È la tecnica tipica per scansioni rapide ed efficaci.

3. **Scansione porte UDP**  
   Invia probe UDP verso le porte target:  
   - Nessuna risposta → porta aperta/filtrata.  
   - ICMP Port Unreachable → porta chiusa.  
   - Risposta applicativa → porta aperta e servizio attivo (es. DNS, NTP).  

4. **Analisi servizi**  
   Prova a connettersi alle porte aperte inviando richieste minime (es. HEAD HTTP). Restituisce la prima riga della risposta, utile per riconoscere rapidamente il servizio (es. `HTTP/1.1 200 OK`, `SSH-2.0-OpenSSH_8.9`).

5. **Scansione di range**  
   Permette di definire un intervallo IP (es. `192.168.1.1-192.168.1.50`) ed esegue automaticamente ping e scansione porte per ogni host. I risultati vengono raccolti in dizionari e salvati in CSV.

6. **Interfaccia grafica (PyQt5)**  
   L’app principale (`port_scanner.py`) offre una GUI intuitiva:  
   - input per host o range;  
   - porte singole o intervalli;  
   - checkbox per ICMP/TCP/UDP;  
   - barra di progresso e log in tempo reale;  
   - salvataggio automatico in `scan_results.csv`.  

7. **Output CSV**  
   Ogni scansione salva un file `scan_results.csv` con le seguenti colonne:  
   - Range IP  
   - IP  
   - Stato ICMP  
   - Range Porte  
   - Porte TCP Aperte  
   - Porte UDP Aperte  

---

## 🧰 Struttura dei file
- `icmp_tester.py` — ping ICMP
- `tcp_scanner.py` — SYN scan TCP
- `udp_scanner.py` — probe UDP
- `service_analyzer.py` — banner grabbing minimale
- `ip_range_scanner.py` — orchestratore per range IP
- `port_scanner.py` — interfaccia PyQt5 + log + CSV

---

## ⚠️ Avvertenze legali e di sicurezza

Usa Scansphere solo su reti e dispositivi su cui hai autorizzazione esplicita.

Scansionare reti altrui senza permesso può essere illegale.

Lo strumento è stato creato a scopo educativo e di test.

L’autore non è responsabile per eventuali abusi o usi impropri.

---

## ⚙️ Requisiti e installazione
- Python 3.8+
- Scapy
- PyQt5

Installa tutto con:
```bash
pip install scapy PyQt5
