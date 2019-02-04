'''
resolver.py
===========
'''

import socket, time, signal

def resolves(domain):
    """
	If domain resolves to an A, AAAA or CNAME return True 
	
	Parameters
	----------
	
	domain
		A string such as 'example.com'
	"""
	try:
        #socket.gethostbyname(domain)
		socket.getaddrinfo(domain,80)
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
