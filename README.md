SPF and DMARC validator

## Documentation

<http://www.csbaird.com/software/sdvalidator>

## TODO

- Better processing for DMARC records
- bug with redirect.  Fix REGEX eg 'gmail.com'
    
- [FIXED] bug with non-resolving domain.  Should check SPF record if A or MX
    Made python references local to package `from . import dns_grab`
    Cleaned up old files
