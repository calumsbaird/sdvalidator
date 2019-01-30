import socket, time, signal

def resolves(domain, timeout):
    
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
