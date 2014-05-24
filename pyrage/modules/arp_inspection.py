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
from pyrage.utils import InvalidInterface
from pyrage.utils import InvalidVlanRange
from pyrage.utils import validateVlanRange

class ArpInspection(IPlugin):
    def __init__(self):
        self.trustedPorts = None
        self.vlanRange = None

    def addTrustedInt(self,trustedInterface):
        if trustedInterface is None:
            raise InvalidInterface(
                ":arp_inspection:Invalid arp inspection trusted interface specified: '{0}'".format(trustedInterface),
                trustedInterface)
        else:
            if self.trustedPorts is None:
                self.trustedPorts = []
            self.trustedPorts.append(trustedInterface)

    def addVlanRange(self,vlanRange):
        if vlanRange=='0':
            self.vlanRange=None
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":arp_inspection:Invalid arp inspection vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange


    def parseContext(self,contextToParse,*args):
        for arp in contextToParse.iter('arp_inspection'):
            vlanRange = arp.find('vlan_range')
            if vlanRange is not None:
                self.addVlanRange(vlanRange.text)
            for interface in arp.iter('trusted_interface'):
                self.addTrustedInt(interface.text)


