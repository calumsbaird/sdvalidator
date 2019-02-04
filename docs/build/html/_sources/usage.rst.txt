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
