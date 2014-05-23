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

from pyrage.utils import ErrRequiredData

"""
TODO
aaa method list, add id attrbute. because name could be same for different lists. Add name to subelements
aaa method list, add apply_on? line,enable,con
"""
class AAA(IPlugin):
    def __init__(self):
        self.hosts = {}
        self.groups = {}
        self.methodsLists={}

    def addMethodList(self,listName,types,methods):
        if not len(listName)>0 or not len(types)>0 or not len(methods)>0:
            raise ErrRequiredData(":aaa:Not enough data given to specify an aaa method list.",listName,types,methods)
        if listName not in self.methodsLists:
            self.methodsLists[listName] = {}
        list = self.methodsLists[listName]
        list['type'] = {}
        for type in types:
            # test if given types dict has good structure
            if isinstance(types[type],str):
                list['type'][type] = types[type]
            else:
                raise ErrRequiredData(":aaa:Invalid method list type specified. '{0}'".format(types[type]),
                                             types)
        list['methods'] = []
        for method in methods:
            if len(method) > 0:
                list['methods'].append(method)


    def addGroup(self,groupName,groupType):
        if not len(groupName) > 0 or not len(groupType) > 0:
            raise ErrRequiredData("aaa:Invalid aaa group name or group type specified.",groupName,groupType)

        if groupName not in self.groups:
            self.groups[groupName] = {}
            self.groups[groupName]['hosts'] = []
        group = self.groups[groupName]
        group['type'] = groupType


    def addHost(self,name,host,group,type):
        if not len(name) > 0 or not len(host) > 0:
            raise ErrRequiredData(":aaa:Invald aaa host id or hostname specified.",name,host)
        if group not in self.groups:
            self.groups[group] = {}
            self.groups[group]['hosts'] = [].append(name)
        else:
            self.groups[group]['hosts'].append(name)
        self.hosts[name] = {}
        self.hosts[name]['ip'] = host
        self.hosts[name]['type'] = type

    def parseContext(self,contextToParse,*args):

        for aaa_def in contextToParse.iter('aaa'):
            for group in contextToParse.iter('aaa_group'):
                self.addGroup(
                        group.attrib['id'],
                        group.attrib['type']
                )

            for host in contextToParse.iter('aaa_host'):
                hostGroup = host.attrib['group']
                self.addHost(
                    host.attrib['id'],
                    host.text,
                    host.attrib['group'],
                    host.attrib['type']
                )
            for list in contextToParse.iter('aaa_method_list'):
                types = {}
                for type in list.iter('type'):
                    types[type.attrib['id']] = type.text
                methods = []
                for method in list.iter('method'):
                    methods.append(method.text)
                self.addMethodList(
                    list.attrib['name'],
                    types,
                    methods
                )



