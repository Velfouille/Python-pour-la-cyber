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
