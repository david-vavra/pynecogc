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
from pyrage.acl import ACLv4
from pyrage.acl import ACLv6
from pyrage.utils import isValidIP
from pyrage.utils import ErrRequiredData
import pyrage.utils

class VTY(IPlugin):
    def __init__(self):
        self.acl=None
        self.acl6=None
        self.protocols = None
        self.vlan = None
        self.gw = None


    def _addProtocol(self,protocol,version=None,timeout=600,retries=3):
        if self.protocols is None:
            self.protocols={}
        if protocol not in self.protocols:
            self.protocols[protocol] = {}
            if version is not None:
                self.protocols[protocol]['version'] = version
            self.protocols[protocol]['timeout'] = timeout
            self.protocols[protocol]['retries'] = retries

    def _addAcl(self,aclInstance):
        if isinstance(aclInstance,ACLv4):
            self.acl = aclInstance
        elif isinstance(aclInstance,ACLv6):
            self.acl6=aclInstance

    def _addGateway(self,gateway):
        if not isValidIP(gateway):
            raise ErrRequiredData(
                    "vty:Invalid gateway IP address given: {0}".format(gateway),
                    gateway
            )

        self.gw = gateway

    def _addVlan(self,vlan):
        try:
            if int(vlan) >= pyrage.utils.VLAN_MIN and int(vlan) <= pyrage.utils.VLAN_MAX:
                self.vlan = vlan
        except ValueError as e:
            raise ErrRequiredData(
                "vty:Invalid vlan identifier specified: '{0}'".format(vlan),
                vlan)


    def parseContext(self,contextToParse,acls):

        for vty in contextToParse.iter('vty'):
            # Parse desired transport protocol and its parameters.
            protocol = vty.find('protocol')
            if protocol is not None:
                if protocol.text == 'ssh':
                    sshParams={}
                    if 'version' in protocol.attrib:
                        sshParams['version'] = protocol.attrib['version']
                    if 'timeout' in protocol.attrib:
                        sshParams['timeout'] = protocol.attrib['timeout']
                    if 'retries' in protocol.attrib:
                        sshParams['retries'] = protocol.attrib['retries']
                    self._addProtocol(protocol.text,**sshParams)
                else:
                    self._addProtocol(protocol.text)
            # Parse id of acl used to limit access to device's vty
            if vty.find('acl_id') is not None:
                aclId = vty.find('acl_id').text
                acl=acls.parseAcl(aclId,4)
                self._addAcl(acl)

            if vty.find('acl6_id') is not None:
                aclId = vty.find('acl6_id').text
                acl=acls.parseAcl(aclId,6)
                self._addAcl(acl)

            if vty.find('vlan') is not None:
                self._addVlan(vty.find('vlan').text)

            if vty.find('gw') is not None:
                self._addGateway(vty.find('gw').text)

