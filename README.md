# Python-pour-la-cyber

## Côté client : 
```
import socket
import sys

TCP_IP = '10.102.252.22'
TCP_PORT = 2000
BUFFER_SIZE = 1024
MESSAGE_TO_SERVER = 'LE MESSAGE EST : Coucou les RT !'


try : 
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
        sys.exit();

tcp_socket.connect((TCP_IP, TCP_PORT))


try :
        tcp_socket.send(MESSAGE_TO_SERVER.encode('utf8'))
except socket.error:
        sys.exit()

print("Message envoyé au serveur avec succès")

data = tcp_socket.recv(BUFFER_SIZE)


tcp_socket.close()

print ("Réponse du serveur :", data)
```

## Côté serveur (se ferme une fois la réponse obtenue)
```
import socket
import sys

TCP_IP_srv = '10.102.252.22'
TCP_PORT = 2000
BUFFER_SIZE = 1024

try:
	tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
	print('Une erreur est apparue pendant la création de la socket')
	sys.exit();
	
tcp_socket.bind((TCP_IP_srv, TCP_PORT))


tcp_socket.listen(3)
print('En écoute ...')


connexion, adresse = tcp_socket.accept()

print('Connecté avec : ', adresse)

data = connexion.recv(BUFFER_SIZE)

print("Message recu du client :", data)

reponse_serveur = 'Merci pour la connexion'
connexion.sendall(reponse_serveur.encode('utf8'))

connexion.close()
```
## Pour maintenir le serveur en écoute (reste en écoute, même après réception du message
```
import socket
import sys

TCP_IP_srv = '10.102.252.22'
TCP_PORT = 2000
BUFFER_SIZE = 1024

try:
	tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
	print('Une erreur est apparue pendant la création de la socket')
	sys.exit();
	
tcp_socket.bind((TCP_IP_srv, TCP_PORT))

#En écout d'une connexion entrante
tcp_socket.listen()
print('En écoute ...')

#En attente d'une connexion
while True :
	connexion, adresse = tcp_socket.accept()
	print('Connecté avec : ', adresse)
	data = connexion.recv(BUFFER_SIZE)
	print("Message recu du client :", data)
	reponse_serveur = 'Merci pour la connexion'
	connexion.sendall(reponse_serveur.encode('utf8'))

connexion.close()
```

# Module Scapy

Pour ouvrir Scapy :
```
sudo scapy
```

Pour filtrer les 4 prochaines trames ICMP :
```
sniff(filter="icmp", iface="eth0", count=4)
```

## Sniffer (socket brute) python3

```
import socket
import struct
import binascii

try:
       raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
except socket.error as e:
       sys.exit();
while True:
       packet = raw_socket.recvfrom(2048)
       ethernet_header = packet[0][0:14]
       eth_header = struct.unpack("!6s6s2s", ethernet_header)
       print('Destination :', binascii.hexlify(eth_header[0]))
       print('Source :', binascii.hexlify(eth_header[1]))
       print('Type :', binascii.hexlify(eth_header[2]))
       ip_header = packet[0][14:34]
       ip_hdr = struct.unpack("!12s4s4s", ip_header)
       print('Source IP :', socket.inet_ntoa(ip_hdr[1]))
       print('Destination IP :', socket.inet_ntoa(ip_hdr[2]))
       
 ```

## Scan de ports TCP avec la fonction tcp_scan(hote, port)

```
from scapy.all import sr1, IP, TCP, conf

def tcp_scan(hote, port):
    tcp_packet = IP(dst=hote)/TCP(dport=port, flags='S')
    response = sr1(tcp_packet, timeout=1, verbose=0)
    
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        print(f"Le port {port} sur l'hôte {hote} est ouvert.")
    else:
        print(f"Le port {port} sur l'hôte {hote} est fermé.")

# Hôte cible
hote = "10.102.252.137"

# Ports à scanner
ports = [80, 22]  # Vous pouvez ajouter d'autres ports ici

# Réaliser le scan pour chaque port
for port in ports:
    tcp_scan(hote, port)
```

## Script résolution DNS

```
import socket

ip_address = "10.108.239.251"
try:
    hostname = socket.gethostbyaddr(ip_address)
    print("Nom de domaine associé à l'adresse IP:", hostname[0])
except socket.herror:
    print("Impossible de résoudre l'adresse IP en nom de domaine.")

```

## Lister les IP d'un nom de domaine
```
import socket

def get_ips_par_recherche_dns(cible, port=None):
    try:
        ip_addresses = socket.gethostbyname_ex(cible)[2]
        return ip_addresses
    except socket.gaierror:
        return []

# Exemple d'utilisation de la fonction
cible = 'iut-acy.local'
port = 443
liste_ip = []

adresses_ip = get_ips_par_recherche_dns(cible, port)
if adresses_ip:
    liste_ip.extend(adresses_ip)
    #print(f"Adresses IP pour la cible {cible}:")
    #for ip in adresses_ip:
        #print(ip)
        
else:
    print(f"Impossible de trouver des adresses IP pour la cible {cible}")
    
print(liste_ip)

```

## Trouver les types d'enregistrement du domaine iut-acy.local
```
import dns.resolver

def resolve_dns_records(target):
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            results[record_type] = []

    return results

target = "iut-acy.local"
results = resolve_dns_records(target)

for record_type, records in results.items():
    if len(records) > 0:
        print(f"{record_type} enregistrements pour {target}:")
        for record in records:
            print(record)
        print()
```


## Analyser IP dest + IP source + port source + flag TCP
```
from scapy.all import *

def analyse_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    for packet in packets:
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_flags = packet[TCP].flags
            tcp_src_port = packet[TCP].sport

            print("Adresse IP Source:", ip_src)
            print("Adresse IP Destination:", ip_dst)
            print("Flag TCP:", tcp_flags)
            print("Port Source:", tcp_src_port)
            print()

# Exemple d'utilisation
pcap_file = 'capture_meta_1.pcap'
analyse_pcap(pcap_file)
```

## Afficher tout un Layer
```
import pyshark

capture = pyshark.FileCapture('trame_echo_1.pcap')


dico_Layer_TCP = {}
n = 0

for pqt in capture:
	dico_Layer_TCP[n] = pqt['TCP']
	n = n+1
	
print(dico_Layer_TCP[2])
```

