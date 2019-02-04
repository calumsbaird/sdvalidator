def pull_spf(domain):
    """
    >>> pull_spf('csbaird.com')
    ['v=spf1 mx -all']

    Get all txt records that look like they are an spf record

    :param str domain: domain like example.com
    :returns: List of records that look like they are spf records.
    :rtype: list
    """
    # Return any record that appears to be an spf record
    return list(filter(lambda s: s.lower().startswith('v=spf'), resolve_record(domain)))


def pull_dmarc(domain):
    """
    >>> pull_dmarc('csbaird.com')
    ['v=DMARC1;  p=reject; pct=100; rua=mailto:root@csbaird.com; ruf=mailto:root@csbaird.com']
    
    Get all txt records that look like they are an dmarc record

    :param str domain: domain like example.com
    :returns: List of records that look like they are dmarc records.
    :rtype: list
    """
        
    # Return any record that appears to be a dmarc record
    return list(filter(lambda s: s.lower().startswith('v=dmarc'),
        resolve_record('_dmarc.'+domain)))


import dns.resolver
resolver = dns.resolver.Resolver()
def resolve_record(domain):
    """
    >>> resolve_record('csbaird.com')
    ['ca3-0eb269d493c84687a2b27e8bea13ca55', 'v=spf1 mx -all']

    Get all txt records associated with a domain.
    If a CNAME gets record of the domain it redirects to.

    :param str domain: domain like example.com
    :returns: List of txt records associated with the domain
    :rtype: list
    """
    try:
        # Get the txt records for the domain
        response = resolver.query(domain, 'TXT')
    except Exception as e:
        #print(e)
        return []  # Returning on any error getting the response
    #except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
    #    return []

    # Return list of records with quotes removed
    return [r.to_text()[1:-1] for r in response]


def pull_sd(domains, cache={}):
    """
    >>> dns_grab.pull_sd(['csbaird.com'])
    {'csbaird.com': {'spf': ['v=spf1 mx -all'], 'dmarc': ['v=DMARC1;  p=reject; pct=100; rua=mailto:root@csbaird.com; ruf=mailto:root@csbaird.com']}}
    
    Get the SPF and DMARC records and store them in a dictionary.

    :param list domains: list of domains.
    :param dict cache: dictionary containing domains mapped to dicts containing spf and dmarc records.
    :returns: cache
    :rtype: dict
    """
     
    # Include records for all the domains in the cache
    for d in domains:
        cache[d] = {'spf':pull_spf(d), 'dmarc':pull_dmarc(d)}
    return cache

if __name__ == '__main__':
    
    print(pull_spf('google.com'))
    print(pull_dmarc('google.com'))
