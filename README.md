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
