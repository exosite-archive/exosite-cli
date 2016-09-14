#!/usr/bin/env python
from setuptools import setup
import sys

classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
Programming Language :: Python
Topic :: Software Development :: Build Tools
Operating System :: Microsoft :: Windows
Operating System :: Unix
Operating System :: MacOS
"""

required = ["requests == 2.7.0", "certifi", "urllib3 >= 1.10", "six == 1.10.0", "prompt-toolkit==1.0.0", "watchdog"]
data_files = []

if sys.version_info < (2, 7, 9):
    # https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning
    required = required + ['pyopenssl', 'ndg-httpsclient', 'pyasn1']

long_description = open('README.md').read()

setup(
    name = 'exosite',
    version = open('VERSION').read().strip(),
    url = 'http://exosite.com',
    author = 'Ivan Lan',
    author_email = 'ivanlan@exosite.com',
    description = 'Command line interface for Exosite Murano.',
    long_description = long_description,
    scripts = ['bin/exosite'],
    keywords = ['exosite', 'm2m', 'iot', 'cli', 'murano'],
    install_requires = required,
    classifiers = filter(None, classifiers.split("\n")),
    data_files = data_files
    )
