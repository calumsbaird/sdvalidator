def pull_spf(domain):
    
    # Return any record that appears to be an spf record
    return list(filter(lambda s: s.lower().startswith('v=spf'), resolve_record(domain)))


def pull_dmarc(domain):
    
    # Return any record that appears to be a dmarc record
    return list(filter(lambda s: s.lower().startswith('v=dmarc'),
        resolve_record('_dmarc.'+domain)))


import dns.resolver
resolver = dns.resolver.Resolver()
def resolve_record(domain):
     
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
    
    # Include records for all the domains in the cache
    for d in domains:
        cache[d] = {'spf':pull_spf(d), 'dmarc':pull_dmarc(d)}
    return cache

if __name__ == '__main__':
    
    print(pull_spf('google.com'))
    print(pull_dmarc('google.com'))
