import sys      # Importa il modulo sys per interagire con l'interprete Python
import csv      # Importa il modulo csv per leggere/scrivere file CSV
import socket   # Importa il modulo socket per funzioni di rete (hostname, IP, ecc.)
from PyQt5.QtWidgets import (   # Importa i widget di PyQt5 per costruire l'interfaccia grafica
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout,
    QTextEdit, QCheckBox, QMessageBox, QProgressBar
)
from PyQt5.QtCore import pyqtSignal, QThread   # Importa i segnali e la classe base per thread in PyQt
from scanner.icmp_tester import icmp_ping      # Importa la funzione per eseguire un ping ICMP
from scanner.service_analyzer import service_analysis  # Importa la funzione di analisi servizi (non usata qui)
from scanner.tcp_scanner import tcp_scan       # Importa la funzione per la scansione TCP
from scanner.udp_scanner import udp_scan       # Importa la funzione per la scansione UDP
import ipaddress   # Importa il modulo per gestire indirizzi e range IP


class ScannerThread(QThread):   # Definisce un thread dedicato alla scansione di rete
    update_text = pyqtSignal(str)     # Segnale: invia testo di log all'interfaccia
    update_progress = pyqtSignal(int) # Segnale: invia percentuali di avanzamento alla progress bar
    update_csv = pyqtSignal(dict)     # Segnale: invia un dizionario con i risultati da salvare nel CSV

    def __init__(self, host, ip_range, ports, check_tcp, check_udp, check_icmp):  # Costruttore del thread
        super().__init__()          # Inizializza la parte QThread
        self.host = host            # Salva l'host singolo da scansionare (o None)
        self.ip_range = ip_range    # Salva il range IP in forma di stringa "start-end" (o None)
        self.ports = ports          # Salva la lista di porte da analizzare
        self.check_tcp = check_tcp  # Flag: se eseguire la scansione TCP
        self.check_udp = check_udp  # Flag: se eseguire la scansione UDP
        self.check_icmp = check_icmp  # Flag: se eseguire il ping ICMP
        self._is_running = True     # Flag interno per consentire lo stop del thread
        self.scan_results = []      # Lista che conterrà i risultati delle scansioni

    def run(self):    # Metodo eseguito automaticamente quando il thread viene avviato
        try:          
            total_tasks = 0   # Contatore del numero totale di attività previste

            if self.ip_range:   # Se è stato fornito un range IP
                start_ip, end_ip = map(lambda x: ipaddress.IPv4Address(x.strip()), self.ip_range.split('-'))  # Converte stringhe in IPv4Address
                total_tasks += (int(end_ip) - int(start_ip) + 1) * (1 if self.check_icmp else 0)  # Aggiunge i task ICMP per ogni IP
                total_tasks += (int(end_ip) - int(start_ip) + 1) * len(self.ports) * (self.check_tcp + self.check_udp)  # Aggiunge i task TCP/UDP

            if self.host:   # Se è stato fornito un host singolo
                total_tasks += 1 if self.check_icmp else 0   # Aggiunge il task ICMP per l'host
                total_tasks += len(self.ports) * (self.check_tcp + self.check_udp)  # Aggiunge i task TCP/UDP per l'host

            completed_tasks = 0   # Contatore dei task completati

            if self.ip_range:   # Se si deve scansionare un range IP
                start_ip, end_ip = map(lambda x: ipaddress.IPv4Address(x.strip()), self.ip_range.split('-'))  # Ricalcola gli estremi del range
                for ip in range(int(start_ip), int(end_ip) + 1):   # Itera su ogni IP del range
                    if not self._is_running:   # Se è stato richiesto lo stop
                        break                   # Interrompe il ciclo
                    ip_str = str(ipaddress.IPv4Address(ip))   # Converte l'intero corrente in stringa IP
                    self.scan_host(ip_str, self.scan_results) # Esegue la scansione per quell'IP e aggiorna i risultati
                    completed_tasks += (1 if self.check_icmp else 0) + len(self.ports) * (self.check_tcp + self.check_udp)  # Aggiorna il contatore
                    self.update_progress.emit(int((completed_tasks / total_tasks) * 100))   # Emette la percentuale di avanzamento

            if self.host and self._is_running:   # Se si deve scansionare un host singolo e il thread è attivo
                self.scan_host(self.host, self.scan_results)  # Esegue la scansione dell'host
                completed_tasks += (1 if self.check_icmp else 0) + len(self.ports) * (self.check_tcp + self.check_udp)  # Aggiorna il contatore
                self.update_progress.emit(int((completed_tasks / total_tasks) * 100))  # Emette la percentuale di avanzamento

            if self._is_running:   # Se la scansione non è stata interrotta
                self.update_progress.emit(100)   # Imposta la barra di progresso al 100%
                self.update_text.emit("<span style='color:green;'>Scansione terminata</span>")  # Invia un messaggio di fine scansione

            for result in self.scan_results:   # Itera su tutti i risultati raccolti
                self.update_csv.emit(result)   # Emette ciascun risultato per la scrittura nel CSV

        except Exception as e:   # Gestione di eventuali eccezioni
            self.update_text.emit(f"Errore durante la scansione: {str(e)}\n")  # Invia il messaggio di errore all'interfaccia

    def scan_host(self, ip, scan_results):   # Esegue la scansione su un singolo host
        is_active = icmp_ping(ip) if self.check_icmp else True   # Esegue ICMP ping se richiesto, altrimenti assume attivo
        status = 'Host attivo' if is_active else 'Host inattivo' # Determina lo stato dell'host
        self.update_text.emit(f"{ip}: {status}\n")   # Invia lo stato all'area di testo dell'interfaccia

        scan_result = {   # Prepara il dizionario con le informazioni base per il CSV
            "Range IP": self.ip_range if self.ip_range else "Singolo IP",  # Indica se proviene da range o host singolo
            "IP": ip,                                                     # Indirizzo IP corrente
            "Stato ICMP": status,                                         # Esito del ping ICMP
            "Range Porte": "" if not is_active else (                     # Intervallo porte (se host attivo e porte fornite)
                f"{min(self.ports)} - {max(self.ports)}" if (self.ports and (self.check_tcp or self.check_udp)) else ""
            ),
            "Porte TCP Aperte": "" if not is_active or not self.check_tcp else "Vuoto",  # Placeholder per porte TCP aperte
            "Porte UDP Aperte": "" if not is_active or not self.check_udp else "Vuoto"   # Placeholder per porte UDP aperte
        }

        if is_active:   # Se l'host risponde
            if self.check_tcp:   # Se è abilitata la scansione TCP
                open_tcp_ports = tcp_scan(ip, self.ports)  # Esegue la scansione TCP sulle porte indicate
                self.add_port_results(ip, open_tcp_ports, scan_result, "Porte TCP Aperte", "TCP")  # Aggiorna i risultati TCP

            if self.check_udp:   # Se è abilitata la scansione UDP
                open_udp_ports = udp_scan(ip, self.ports)  # Esegue la scansione UDP sulle porte indicate
                self.add_port_results(ip, open_udp_ports, scan_result, "Porte UDP Aperte", "UDP")  # Aggiorna i risultati UDP

        scan_results.append(scan_result)  # Aggiunge il risultato per questo host alla lista complessiva

    def add_port_results(self, ip, open_ports, scan_result, port_key, protocol):   # Aggiorna il dizionario risultati con le porte trovate
        if open_ports:   # Se sono state trovate porte aperte
            self.update_text.emit(f"Porte {protocol} aperte per {ip}: {open_ports}\n")   # Invia la lista porte all'interfaccia
            scan_result[port_key] = ', '.join(map(str, open_ports)) if open_ports else "Vuoto"  # Salva le porte come stringa separata da virgole
        else:   # Se non sono state trovate porte aperte
            self.update_text.emit(f"Nessuna porta {protocol} aperta per {ip}\n")   # Invia un messaggio di assenza porte aperte

    def stop(self):   # Metodo chiamato per fermare la scansione
        self._is_running = False  # Imposta il flag interno a False per interrompere i loop

class PortScannerApp(QWidget):   # Classe della finestra principale dell'applicazione
    def confirm_exit(self):   # Mostra una finestra di conferma prima di uscire
        msg_box = QMessageBox(self)   # Crea la finestra di dialogo
        msg_box.setWindowTitle('Conferma Uscita')   # Imposta il titolo
        msg_box.setText("Sei sicuro di voler uscire?")   # Imposta il testo della domanda
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)   # Aggiunge i pulsanti standard Sì/No
        yes_button = msg_box.button(QMessageBox.Yes)   # Ottiene il riferimento al pulsante Sì
        no_button = msg_box.button(QMessageBox.No)     # Ottiene il riferimento al pulsante No
        yes_button.setText("Sì")   # Imposta l'etichetta del pulsante Sì
        no_button.setText("No")    # Imposta l'etichetta del pulsante No

        reply = msg_box.exec_()   # Mostra la finestra e attende la risposta dell'utente

        if reply == QMessageBox.Yes:   # Se l'utente ha cliccato Sì
            self.close()   # Chiude la finestra (e l'applicazione)

    def __init__(self):   # Costruttore della finestra principale
        super().__init__()   # Inizializza la classe base QWidget
        self.initUI()   # Costruisce l'interfaccia grafica
        self.csv_file = "scan_results.csv"   # Imposta il nome del file CSV per i risultati
        self.init_csv()   # Inizializza il file CSV scrivendo l'intestazione

    def initUI(self):   # Configura tutti i widget e i layout dell'interfaccia
        self.setWindowTitle('Scansphere')   # Imposta il titolo della finestra
        self.setGeometry(100, 100, 500, 600)   # Imposta posizione e dimensioni della finestra
        main_layout = QVBoxLayout()   # Crea il layout verticale principale

        self.label_host = QLabel('Host/IP:')   # Crea l'etichetta per il campo host/IP
        self.entry_host = QLineEdit(self)      # Crea il campo di input per l'host/IP
        self.entry_host.setText(socket.gethostbyname(socket.gethostname()))  # Precompila con l'IP della macchina

        self.label_ip_range = QLabel('Range IP (es: 192.168.1.1-192.168.1.10):')   # Etichetta per il range IP
        self.entry_ip_range = QLineEdit(self)   # Campo di input per il range IP

        self.label_ports = QLabel('Porte (separate da virgole o range, es: 20-80):')   # Etichetta per l'input delle porte
        self.entry_ports = QLineEdit(self)   # Campo di input per le porte

        self.check_icmp = QCheckBox('Ping ICMP')   # Checkbox per il ping ICMP
        self.check_icmp.setChecked(True)           # Imposta il checkbox come selezionato
        self.check_icmp.setEnabled(False)          # Disabilita la modifica (sempre attivo)
        self.check_icmp.setStyleSheet('color: black')  # Forza il testo in nero
        self.check_tcp = QCheckBox('Scansione TCP')    # Checkbox per abilitare scansione TCP
        self.check_udp = QCheckBox('Scansione UDP')    # Checkbox per abilitare scansione UDP

        self.button_scan = QPushButton('Avvia Scansione', self)   # Pulsante per avviare la scansione
        self.button_scan.clicked.connect(self.start_scan)         # Collega il pulsante alla funzione di avvio

        self.button_stop = QPushButton('Interrompi Scansione', self)  # Pulsante per fermare la scansione
        self.button_stop.setEnabled(False)                          # Inizialmente disabilitato
        self.button_stop.clicked.connect(self.stop_scan)            # Collega il pulsante alla funzione di stop

        self.progress_bar = QProgressBar(self)   # Crea la barra di progresso
        self.progress_bar.setRange(0, 100)      # Imposta l'intervallo 0–100
        self.progress_bar.setValue(0)           # Imposta il valore iniziale a 0
        self.progress_bar.setVisible(False)     # La rende invisibile finché non parte la scansione

        self.text_output = QTextEdit(self)   # Crea l'area di testo per l'output
        self.text_output.setReadOnly(True)   # Imposta l'area come sola lettura

        self.button_exit = QPushButton('Esci', self)   # Crea il pulsante di uscita
        self.button_exit.clicked.connect(self.confirm_exit)  # Collega il pulsante alla finestra di conferma

        main_layout.addWidget(self.label_host)   # Aggiunge l'etichetta host al layout
        main_layout.addWidget(self.entry_host)   # Aggiunge il campo host al layout
        main_layout.addWidget(self.label_ip_range)   # Aggiunge l'etichetta range IP
        main_layout.addWidget(self.entry_ip_range)   # Aggiunge il campo range IP
        main_layout.addWidget(self.label_ports)      # Aggiunge l'etichetta porte
        main_layout.addWidget(self.entry_ports)      # Aggiunge il campo porte
        main_layout.addWidget(self.check_icmp)       # Aggiunge il checkbox ICMP
        main_layout.addWidget(self.check_tcp)        # Aggiunge il checkbox TCP
        main_layout.addWidget(self.check_udp)        # Aggiunge il checkbox UDP
        main_layout.addWidget(self.button_scan)      # Aggiunge il pulsante Avvia
        main_layout.addWidget(self.button_stop)      # Aggiunge il pulsante Stop
        main_layout.addWidget(self.progress_bar)     # Aggiunge la barra di progresso
        main_layout.addWidget(self.text_output)      # Aggiunge l'area di testo

        bottom_layout = QHBoxLayout()   # Crea un layout orizzontale inferiore
        bottom_layout.addStretch()      # Aggiunge spazio elastico a sinistra
        bottom_layout.addWidget(self.button_exit)  # Aggiunge il pulsante Esci a destra

        main_layout.addLayout(bottom_layout)   # Inserisce il layout inferiore nel principale

        self.setLayout(main_layout)   # Applica il layout principale alla finestra

    def init_csv(self):   # Crea o sovrascrive il file CSV inserendo l'intestazione
        with open(self.csv_file, mode='w', newline='') as file:   # Apre il file CSV in scrittura
            writer = csv.DictWriter(file,   # Crea un writer che usa le chiavi del dizionario
                                    fieldnames=["Range IP", "IP", "Stato ICMP", "Range Porte", "Porte TCP Aperte", "Porte UDP Aperte"])  
            writer.writeheader()   # Scrive la riga di intestazione nel file

    def parse_ports(self, ports_text):   # Converte il testo delle porte in una lista di interi
        ports = set()   # Usa un set per evitare duplicati
        for part in ports_text.split(','):   # Divide l'input per virgole
            part = part.strip()   # Rimuove spazi esterni
            if '-' in part:   # Se la parte contiene un trattino, è un intervallo
                try:
                    start_port, end_port = map(int, part.split('-'))   # Converte gli estremi in interi
                    if start_port > end_port:   # Controlla che l'intervallo sia valido
                        raise ValueError
                    ports.update(range(start_port, end_port + 1))   # Aggiunge tutte le porte dell'intervallo
                except ValueError:
                    QMessageBox.warning(self, "Input Errato", f"Range di porte non valido: {part}")   # Mostra un avviso di errore
                    return []   # Ritorna lista vuota in caso di errore
            elif part.isdigit():   # Se è un numero singolo
                ports.add(int(part))   # Aggiunge la porta al set
            else:   # Formato non valido
                QMessageBox.warning(self, "Input Errato", f"Formato porta non valido: {part}")   # Mostra un avviso di errore
                return []   # Ritorna lista vuota in caso di errore
        return sorted(ports)   # Ritorna una lista ordinata delle porte

    def start_scan(self):   # Avvia la scansione in base ai parametri inseriti
        self.button_scan.setEnabled(False)   # Disabilita il pulsante Avvia
        self.button_stop.setEnabled(True)    # Abilita il pulsante Stop
        ip_range = self.entry_ip_range.text()   # Legge il testo del range IP
        if ip_range:   # Se è presente un range IP
            self.entry_host.clear()   # Svuota il campo host per evitare ambiguità
        host = self.entry_host.text() if not ip_range else None   # Usa l'host solo se il range è vuoto
        ports_text = self.entry_ports.text()   # Legge il testo delle porte

        if not host and not ip_range:   # Se mancano sia host che range
            QMessageBox.warning(self, "Input Errato", "Inserisci un host o un range di IP da scansionare.")   # Mostra un avviso
            self.button_scan.setEnabled(True)   # Riabilita il pulsante Avvia
            self.button_stop.setEnabled(False)  # Disabilita il pulsante Stop
            return   # Interrompe la funzione

        ports = self.parse_ports(ports_text) if ports_text.strip() else []   # Converte l'input delle porte in lista
        if not ports and (self.check_tcp.isChecked() or self.check_udp.isChecked()):   # Se servono porte ma non ci sono
            QMessageBox.warning(self, "Input Errato", "Inserisci un range di porte valido per scansioni TCP/UDP.")   # Mostra un avviso
            self.button_scan.setEnabled(True)   # Riabilita Avvia
            self.button_stop.setEnabled(False)  # Disabilita Stop
            return   # Interrompe la funzione

        self.text_output.clear()   # Pulisce l'area di output testuale
        self.progress_bar.setVisible(True)   # Mostra la barra di progresso
        self.progress_bar.setValue(0)        # Imposta la barra a 0

        self.scan_thread = ScannerThread(host, ip_range, ports,   # Crea il thread di scansione con i parametri correnti
                                         self.check_tcp.isChecked(),
                                         self.check_udp.isChecked(),
                                         self.check_icmp.isChecked())

        self.scan_thread.update_text.connect(self.append_text)   # Collega il segnale di testo alla funzione che scrive nell'output
        self.scan_thread.update_progress.connect(self.update_progress)   # Collega il segnale di progresso all'aggiornamento della barra
        self.scan_thread.update_csv.connect(self.write_csv)      # Collega il segnale per scrivere righe nel CSV
        self.scan_thread.finished.connect(self.scan_finished)    # Collega il segnale di fine scansione al gestore
        self.scan_thread.start()   # Avvia l'esecuzione del thread

    def stop_scan(self):   # Ferma la scansione in corso
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():   # Verifica che il thread esista ed è attivo
            self.scan_thread.stop()   # Imposta il flag di stop nel thread
            self.scan_thread.finished.connect(lambda: self.scan_finished(interrupted=True))   # Alla fine segnala interruzione

    def scan_finished(self, interrupted=False):   # Gestisce la fine della scansione
        self.button_scan.setEnabled(True)   # Riabilita il pulsante Avvia
        self.button_stop.setEnabled(False)  # Disabilita il pulsante Stop
        self.progress_bar.setValue(100)     # Porta la barra al 100%
        if interrupted:   # Se la scansione è stata interrotta
            self.append_text("<span style='color:green;'>Scansione interrotta</span>\n")   # Aggiunge un messaggio nell'output

    def append_text(self, text):   # Aggiunge una riga di testo all'area di output
        self.text_output.append(text)  # Inserisce il testo nel QTextEdit

    def update_progress(self, value):   # Aggiorna il valore della barra di progresso
        self.progress_bar.setValue(value)  # Imposta il valore della progress bar

    def write_csv(self, data):   # Scrive una riga di risultati nel file CSV
        with open(self.csv_file, mode='a', newline='') as file:   # Apre il file in modalità append
            writer = csv.DictWriter(                              # Crea un writer basato su dizionari
                file,
                fieldnames=["Range IP", "IP", "Stato ICMP", "Range Porte", "Porte TCP Aperte", "Porte UDP Aperte"]
            )
            writer.writerow(data)   # Scrive nel CSV i valori contenuti nel dizionario 'data'


if __name__ == '__main__':                 # Esegue il seguente blocco solo se il file è eseguito direttamente
    app = QApplication(sys.argv)           # Crea l'applicazione Qt e passa gli argomenti della riga di comando
    scanner = PortScannerApp()             # Istanzia la finestra principale dell'applicazione
    scanner.show()                         # Mostra la finestra all'utente
    sys.exit(app.exec_())                  # Avvia il loop degli eventi Qt e termina restituendo il codice di uscita