#!/usr/bin/env python

__author__ = 'David Vavra'

'''
@author: David Vavra

This script performs the installation of Pyrage. Core modules, altogether with example
mako templates, xml network definition and fundamental modules.
'''

from distutils.core import setup

setup(name='Pyrage',
      version='0.1',
      description='Python network config assessor and generator.'
      'that gathers information about physical inventory of networking hardware.',
      author='David Vavra',
      author_email='vavra.david@email.cz',
      platforms=['GNU/Linux'],
      license='GNU',
      packages=['pyrage',
                'pyrage.modules',
                ],
      data_files=[('/usr/local/etc/pyrage/mako/', ['pyrage/mako/cisco_genconf.mako',
                                                   'pyrage/mako/cisco_ncat.mako']),
                  ('/usr/local/bin/',['ncat_xmlconfig',
                                      'pyge'])
                  ]
     )