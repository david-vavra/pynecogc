#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Copyright (C) 2014  David Vavra  (vavra.david@email.cz)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
from yapsy.IPlugin import IPlugin

class VTP(IPlugin):

    def __init__(self):
        self.mode=None
        self.domain=None
        self.version=None

    def parseContext(self,context,*args):
        for vtp in context.iter('vtp'):
            if vtp.find('mode') is not None:
                self.mode=vtp.find('mode').text
            if vtp.find('version') is not None:
                self.version=vtp.find('version').text
            if vtp.find('domain') is not None:
                self.domain=vtp.find('domain').text

