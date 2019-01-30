import socket, time, signal

def resolves(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def filter_resolving_domains(domains, verbose=False):
    if not verbose:
        return list(filter(lambda d: resolves(d), domains))
    else:
        resolving_domains = []
        for i in range(len(domains)):
            if resolves(domains[i]):
                resolving_domains.append(domains[i])
            print('\rResolving {}/{} domains'.format(i+1, len(domains)), end='')
    print()
    return resolving_domains

if __name__ == '__main__':
    print(filter_resolving_domains(['google.com', 'asdf.google.com',
        'facebook.com']))
