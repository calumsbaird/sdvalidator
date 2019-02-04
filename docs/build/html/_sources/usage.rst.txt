Usage
=====

From command line
-----------------

Command line arguments
^^^^^^^^^^^^^^^^^^^^^^
	
.. code-block:: console

	$ sdvalidate google.com
	google.com SPF: VALID DMARC: VALID

File IO
^^^^^^^

.. code-block:: console

	$ cat domains.txt
	google.com
	csbaird.com
	github.com
	
	$ cat domains.txt | sdvalidate
	google.com SPF: VALID  DMARC: VALID
	csbaird.com SPF: VALID  DMARC: VALID
	github.com SPF: VALID  DMARC: VALID

Python Usage
------------

Given a list of domains find which domains have valid spf and dmarc records and cache the results.  Optionally pickle the output.::
    
    from sdvalidator import *
    domains = ['csbaird.com','google.com','github.com']
    cache = validate_sd(domains,verbose=True)
    print(cache['csbaird.com']['spf_validity']) # VALID
    
    import pickle
    with open('backup.pickle','wb') as f:
        pickle.dump(cache, f)
