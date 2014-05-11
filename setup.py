#!/usr/bin/env python

__author__ = 'David Vavra'

'''
@author: David Vavra

This script performs the installation of Pyrage. Core modules, altogether with example
mako templates, xml network definition and fundamental modules.
'''

from setuptools import setup

setup(name='Pyrage',
      version='0.1',
      description='Python network config assessor and generator.',
      author='David Vavra',
      author_email='vavra.david@email.cz',
      platforms=['GNU/Linux'],
      license='GNU',
      packages=['pyrage',
                'pyrage.modules'
                ],
      package_data={'pyrage.modules':['*.yapsy-plugin']},
      data_files=[('/usr/local/etc/pyrage/mako/', ['pyrage/mako/cisco_genconf.mako',
                                                   'pyrage/mako/cisco_ncat.mako',
                                                   'pyrage/mako/comware_ncat.mako',
                                                   'pyrage/mako/comware_genconf.mako']),
                    ('/usr/local/bin/', ['ncat_xmlconfig','pyge'])
                  ]
     )
