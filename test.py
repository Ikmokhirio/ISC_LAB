import socket
domainName = input('Enter the domain name: ')
print(socket.gethostbyname(domainName))
