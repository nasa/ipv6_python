#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='ipv6',
      version='0.1',
      description='Advanced IPv6 Socket Manipulation for Python',
      author='Joseph Ishac',
      author_email='jishac@nasa.gov',
      ext_modules=[Extension('ipv6', ['src/ipv6.c'])],
      )

