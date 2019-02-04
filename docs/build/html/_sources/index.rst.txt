.. sdvalidator documentation master file, created by
   sphinx-quickstart on Mon Feb  4 09:14:09 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to sdvalidator's documentation!
=======================================


.. toctree::
    :maxdepth: 2
    :caption: Contents:

    installation
    usage
    functions

Quick Start
===========

Command line
^^^^^^^^^^^^

.. code-block:: console

    $ pip3 install sdvalidator
    $ sdvalidate csbaird.com
    VALID

Script
^^^^^^

test.py::

    from sdvalidator import *
    domains = ['csbaird.com','google.com','github.com']
    cache = validate_sd(domains,verbose=True)
    print(cache['csbaird.com']['spf_validity']) # VALID

.. code-block:: console

    $ python3 test.py
    VALID


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
