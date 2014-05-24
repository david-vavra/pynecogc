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
from pyrage.utils import validateVlanRange
from pyrage.utils import InvalidVlanRange

class IP_Source_Guard(IPlugin):

    def __init__(self):
        self.vlanRange=None

    def addVlanRange(self,vlanRange):
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":ip_source_guard:Invalid IP source guard vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange

    def parseContext(self,context,*args):
        for ipsg in context.iter('ip_source_guard'):
            if ipsg.find('vlan_range') is not None:
                self.addVlanRange(ipsg.find('vlan_range').text)


