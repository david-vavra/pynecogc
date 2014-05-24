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
from pyrage.utils import *

class URPF(IPlugin):
    def __init__(self):
        self.mode=None
        self.validModes=['strict','loose']

    def changeMode(self,mode):
        if mode.lower() not in self.validModes:
            raise ErrRequiredData(":urpf:Invalid default mode specified: '{0}'".format(
                mode
            ))
        self.mode=mode

    def parseContext(self,context,*args):
        for urpf in context.iter('urpf'):
            if 'mode' not in urpf.attrib:
                raise ErrRequiredData("No urpf mode specified. Attribute 'mode' is missing.")
            self.changeMode(urpf.attrib['mode'])



