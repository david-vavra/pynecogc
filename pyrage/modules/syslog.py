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

class Syslog(IPlugin):
    def __init__(self):
        self.hosts=None
        self.facility=None
        self.severity=None

    def addServer(self,id,host):
        self.hosts={}
        if len(host)>0 and id is not None:
            self.hosts[id]=host

    def changeFacility(self,facility):
        self.facility=facility

    def changeSeverity(self,severity):
        self.severity=severity

    def parseContext(self,context,*args):
        for syslog in context.iter('syslog'):
            if 'severity' in syslog.attrib:
                self.changeSeverity(syslog.attrib['severity'])
            if 'facility' in syslog.attrib:
                self.changeSeverity(syslog.attrib['facility'])
            for host in syslog.iter('host'):
                self.addServer(
                    host.attrib['id'],
                    host.text
                )
