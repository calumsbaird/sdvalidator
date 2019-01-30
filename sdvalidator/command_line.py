def sdvalidate():

    # Take std input
    import sys, argparse
    from .resolver import resolves
    from .validate import validate_sd 

    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(domain,end='')
        if not resolves(domain):
            print(domain,'DOES NOT RESOLVE')
        else:
            d = validate_sd([domain])
            print( domain,\
                'SPF:',d[domain]['spf_validity'],\
                'DMARC:',d[domain]['dmarc_validity'] \
                )
    else:
        cache = {}
        for domain in sys.stdin:
            domain = domain[:-1]
            if not resolves(domain):
                print(domain,'DOES NOT RESOLVE')
            else:
                d = validate_sd([domain], cache=cache)
                print( domain,\
                    'SPF:',d[domain]['spf_validity'],\
                     ' DMARC:',d[domain]['dmarc_validity'] \
                    )



def sdresolves():
    
    # Take std input
    import sys, argparse

    parser = argparse.ArgumentParser()
    #parser.add_argument()
    #args = parser.parse_args()
    
    i = 0
    # Get domains from std input
    from sys import stdin
    from .resolver import resolves 
    for raw in stdin:
        domain = raw[:-1] # Strip new line
        
        # Check wether the domain resolves
        #from resolver import resolves
        
        if resolves(domain):
            print(domain)
            #print('\r'+domain, "\n{}".format(i), end='')
        i += 1
    #print('\r')
    

def spfcat():
    from sys import stdin
    from .dns_grab import pull_spf
    for raw in stdin:
        domain = raw[:-1]
        records = pull_spf(domain)
        if len(records) == 1:
            print(domain, records[0])
        else:
            print(domain, records)
def dmarccat():
    from sys import stdin
    from .dns_grab import pull_dmarc
    for raw in stdin:
        domain = raw[:-1]
        records = pull_dmarc(domain)
        if len(records) == 1:
            print(domain, records[0])
        else:
            print(domain, records)

