import sdvalidator, re
def validate_spf(domain, cache={}, depth=0):
    
    # Get spf record
    if not domain in cache:
        sdvalidator.pull_sd([domain],cache=cache)
    records = cache[domain]['spf']
    
    # Check it is valid length
    if len(records) == 0:
        return 'MISSING'
    elif len(records) > 1:
        return 'INVALID'
 
    # Check record follow general syntax
    SPF_REGEX = re.compile("^v=spf1[ \t]+[+?~-]?(?:(?:all)|(?:ip4(?:[:][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?(?:/[0-9]{1,2})?)|(?:ip6(?:[:]([0-9A-Fa-f]{0,4}:){1,5}[0-9A-Fa-f]{0,4})?(?:/[0-9]{1,2})?)|(?:a(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+)?(?:/[0-9]{1,2})?)|(?:mx(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+)?(?:/[0-9]{1,2})?)|(?:ptr(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:exists(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:include(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:redirect(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:exp(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|)(?:(?:[ \t]+[+?~-]?(?:(?:all)|(?:ip4(?:[:][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})?(?:/[0-9]{1,2})?)|(?:ip6(?:[:]([0-9A-Fa-f]{0,4}:){1,5}[0-9A-Fa-f]{0,4})?(?:/[0-9]{1,2})?)|(?:a(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+)?(?:/[0-9]{1,2})?)|(?:mx(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+)?(?:/[0-9]{1,2})?)|(?:ptr(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:exists(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:include(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:redirect(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|(?:exp(?:[:][A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+))|))*)?$")
    
    if not SPF_REGEX.match(records[0]):
        return 'INVALID'
    
    # Check there isnt too many lookups
    try:
        evaluate_record(records[0], domain, depth)
        return 'VALID'
    except LookupError:
        return 'INVALID'
    

# Recursive function to check validity of spf record
import re
SPF_MECHANISM_REGEX_STRING = "([+\-~?])?(mx|ip4|ip6|exists|include|all|a|redirect|exp|ptr|v)[:=]?([\w+/_.:\-{%}]*)"
SPF_MECHANISM_REGEX = re.compile(SPF_MECHANISM_REGEX_STRING)

def evaluate_record(spf_record, domain, depth=0, void=0):
    
    # A maximum depth of 10 lookups are allowed as per SPF RFC
    if depth >= 10:
        raise LookupError("max 10 spf lookups exceeded")
 
   # A maximum depth of 2 void lookups are allowed as per SPF RFC
    if void >= 2:
        raise LookupError("max 2 void lookups exceeded")
    
   # Get each part of the spf record 
    for match in re.findall(SPF_MECHANISM_REGEX, spf_record):
        qual = match[0]
        mech = match[1].strip()
        value = match[2].strip()
        
        if mech == "include":
            depth+=1
            validate_spf(value,depth=depth)
            #process_domain_spf(value, depth)
        elif mech == "a":
            depth+=1
            #if value == "":
                #resolve_record(domain, "A")
            #else:
                #resolve_record(value, "A")
        elif mech == "mx":
            depth+=1
            #if value == "":
                #resolve_record(domain, "MX")
            #else:
                #resolve_record(value, "MX")
        elif mech == "ip4" or mech == "ip6":
            pass
            # validate_ip(value) # TODO validate ip with
            # ipaddress.ip_network(address)
        elif mech == "redirect":
            depth+=1
            validate_spf(value, depth)
        elif mech == "exists":
            depth+=1
            # Resolution not implemented
            # J had commented out
            #if value == "":
            #    resolve_record(domain, "A")
            #else:
            #    resolve_record(value, "A")
        elif mech == "ptr":
            depth+=1
            # Resolution not implemented
            # J had commented out
            #if value == "":
            #    resolve_record(domain, "PTR")
            #else:
            #    resolve_record(value, "PTR")
            
            #print "Use of PTR is discouraged"
        elif mech == 'v':
            pass
        elif mech == 'all':
            assert value == ''
            assert qual in '+-?~' # define '+' as invalid
        else:
            # Invalid mechanism
            print('here')
            raise LookupError('invalid mechanism')

# DMARC regex
DMARC_REGEX = re.compile("v=DMARC1;.*p=.*")


import tldextract
def validate_dmarc(domain, cache={}):
    
    # TODO improve this function

    # Get records
    if not domain in cache:
        sdvalidator.pull_sd([domain],cache=cache)
    records = cache[domain]['dmarc']
    
    # Check root domain if no record
    if len(records) == 0:
        tld = tldextract.extract(domain)
        domain = '{}.{}'.format(tld.domain,tld.suffix)

    # Check cache
    if not domain in cache:
        sdvalidator.pull_sd([domain],cache=cache)
    records = cache[domain]['dmarc']

    # Check basic errors
    if len(records) == 0:
        return 'MISSING'
    elif len(records) > 1:
        return 'INVALID'
    record = records[0]
    # Check REGEX
    if DMARC_REGEX.match(record):
        return 'VALID'
    else:
        return 'INVALID'
    
    
    

def validate_sd(domains, cache={}, verbose=False):
    i = 0
    for d in domains:
        if verbose:
            i += 1
            print('\rValidating {}/{} records'.format(i,len(domains)), end='')


        # Get the spf and dmarc records
        if d not in cache:
           sdvalidator.pull_sd([d],cache=cache)
        
        spf = cache[d]['spf']
        dmarc = cache[d]['dmarc']

        cache[d]['spf_validity'] = validate_spf(d,cache=cache)
        cache[d]['dmarc_validity'] = validate_dmarc(d,cache=cache)
    
    if verbose: print()
    return cache


if __name__ == '__main__':
    print(validate_sd(['csbaird.com']))
