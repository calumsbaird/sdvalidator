from sdvalidator import *
#domains = ['csbaird.com','google.com','github.com']
#cache = validate_sd(domains,verbose=True)

#assert cache['csbaird.com']['spf_validity'] == 'VALID' # VALID

# Q1.
cache = {'test.com': {'spf': ['v=spf1 include:sge.net include:spf.swiftdigital.com.au include:spf1.cms.test.com.au include:mailrelay.t1cloud.com ip4:233.120.145.11 ip4:233.110.146.98 ip4:233.25.173.106 ip4:234.252.210.42 -all']} }
assert validate_spf('test.com',cache) == 'VALID'
## Q1. with redirects?
valid = {'spf': ['v=spf1 -all']}
cache = {'test.com': {'spf': ['v=spf1 include:sge.net include:spf.swiftdigital.com.au include:spf1.cms.test.com.au include:mailrelay.t1cloud.com ip4:233.120.145.11 ip4:233.110.146.98 ip4:233.25.173.106 ip4:234.252.210.42 -all']}, 'sge.net': valid, 'spf.swiftdigital.com.au':valid, 'spf1.cms.test.com.au':valid, 'mailrelay.t1cloud.com':valid, }
assert validate_spf('test.com',cache) == 'VALID'

# Q2.
record = "v=spf1 include:example.com._nspf.vali.email include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email ~all"
cache = {'test.com': {'spf': [record]}}
#assert validate_spf('test.com',cache) == 'VALID' # FAILING TODO BUG

# Q3
x = 'sge.net.'
print(resolves(x))
print(pull_spf(x))
record = "v=spf1 include:sge.net. mx -all"
cache = {'test.com': {'spf':[record]}, 'sge.net': {'spf':valid}}
#assert validate_spf('test.com',cache) == 'VALID' # FAILING TODO BUG

# Q4
record = "v=spf1 ip4:161.146.236.60 ip4:161.146.236.61 -all"
cache = {'test.com': {'spf': [record]}}
assert validate_spf('test.com', cache) == 'VALID'

# Q5
record = "v=spf1 redirect=_spf.parksaustralia.gov.au"
cache = {'test.com': {'spf': [record]}}
#assert validate_spf('test.com', cache) == 'VALID' # FAILING TODO BUG

# Q6
record = "v=spf1 include:1.com ip4:1.1.1.1 include:2.com"
cache = {'test.com': {'spf': [record]}}
assert validate_spf('test.com', cache) == 'VALID'


exit()

import pickle
with open('backup.pickle','wb') as f:
    pickle.dump(cache, f)
