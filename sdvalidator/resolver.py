"""
resolver.py
===========
"""

import socket, time, signal

def resolves(domain):
    """
    >>> resolves('csbaird.com')
    True
    
    If domain resolves to an A, AAAA or CNAME return True 
    
    :param str domain: A domain such as 'example.com' 
    :returns: True if resolves to an address
    :rtype: int
    """
    try:
        #socket.gethostbyname(domain)
        socket.getaddrinfo(domain,80)
        return True
    except socket.gaierror:
        return False

def filter_resolving_domains(domains, verbose=False):
    """
    >>> filter_resolving_domains(['csbaird.com','fake.csbaird.com'])
    ['csbaird.com']

    Filters out any non-resolving domain from a list.
    
    :param list domains: A list of str domains
    :param bool verbose: Optionally print progress of filter
    :returns: List of resolving domains
    :list:
    """
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
