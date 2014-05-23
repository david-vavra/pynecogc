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

import xml.etree.ElementTree as xmlet
from pyrage.acl import ACL
from pyrage.utils import ErrRequiredData
from pyrage.utils import ErrOptionalData
from yapsy.PluginManager import PluginManager
import copy

from yapsy import logging

import os

class XML_NetworkParser():

    def __init__(self,logger,definitionsFile):

        self.logger = logger

        """
         Instance of currently parsed device, kept in order to its attributes be
         accessible within the context of methods called by parseDevice method.
        """
        self.currentlyParsedDevice=None

        """ load XML description of the network (devices, acls, groups) """
        try:
            self.network = xmlet.parse(definitionsFile)
        except IOError as e:
            self.logger.log(
                            'critical',"Exiting! Unable to parse file '{f}': {err}".format(
                            f=definitionsFile,err=e.strerror)
                            )
            raise SystemExit(1)
        except SyntaxError as e:
            self.logger.log(
                'critical',"Exiting! Unable to parse file '{f}': {err}".format(
                    f=definitionsFile,err=e.msg)
            )
            raise SystemExit(1)

        self.devicesXml=None
        for devices in self.network.iter('devices'):
            self.devicesXml=devices
        self.groupsXml=None
        for groups in self.network.iter('groups'):
            self.groupsXml=groups

        if self.devicesXml is None or self.groupsXml is None:
            self.logger.log(
                'critical',"Exiting! Unable to parse file '{f}': Schema of the file is probably not valid.".format(
                    f=definitionsFile)
            )

        """ Initialize container for acls"""
        self.acls = ACL(self.network)

    def parseDevice(self,dev):

        self.currentlyParsedDevice=dev

        deviceInstances = dev.instances
        deviceDef=None

        for device in self.devicesXml.iter('device'):
            if device.find('fqdn').text == dev.fqdn:
                deviceDef = device
                break
        if deviceDef is None:
            self.logger.log('error',"Device '{dev}' not found in the XML file.".format(dev=dev.fqdn))
            return
        
        if deviceDef.find('vendor') is not None:
            dev.vendor = deviceDef.find('vendor').text
        if deviceDef.find('type') is not None:
            dev.type = deviceDef.find('type').text
        if deviceDef.find('l2') is not None:
            dev.l2=True if deviceDef.find('l2').text.lower()=='true' else False
        if deviceDef.find('l3') is not None:
            dev.l3=True if deviceDef.find('l3').text.lower()=='true' else False
        if deviceDef.find('ipv6') is not None:
            dev.ip6=True if deviceDef.find('ipv6').text.lower()=='true' else False
        """ TODO, possibly add ipv4 tag into devices.xml """
        dev.ip4=True

        dev.groups=deviceDef.attrib['groups'].split(',') if 'groups' in deviceDef.attrib else []

        for member in dev.groups:
            for group in self.groupsXml.iter('group'):
                if group.attrib['id'] == member:
                    """ parse attributes of the given group """
                    self._parseContext(group,deviceInstances)

        """ parse attributes defined within the definition of a device,
         possibly overrides previously parsed data.
        See implementation of the particular plugin to clarify the inheritance alg.
        """
        self._parseContext(deviceDef,deviceInstances)

        self.currentlyParsedDevice=None


    def _parseContext(self,context,instances):
        """
            Parses given context and keeps its parameters as the particular
            instance attributes.
            Later calls of this or other methods may overwrite those.

            MEMBER_GROUP attributes (in as-in-file order) < DEVICE attributes
        """
        for name,instance in instances.items():
            try:
                instance.parseContext(context,self.acls)
            except ErrOptionalData as e:
                self.logger.log('warning',self.currentlyParsedDevice.fqdn+e.message)
            except ErrRequiredData as e:
                self.logger.log('error',self.currentlyParsedDevice.fqdn+e.message)

        return

class Device():
    """ Class representing the particular device and its attributes (plugins/modules are
    kept in the dictionary).
    """
    def __init__(self,deviceName):
        self.instances = copy.deepcopy(instances)

        self.groups=[]
        self.fqdn = deviceName
        self.vendor = ""
        self.type = ""
        self.ip4=False
        self.ip6=False
        self.l2=False
        self.l3=False


""" load the plugins """
PLUGIN_PATH=os.path.dirname(os.path.realpath(__file__)).split('/')
PLUGIN_PATH='/'.join(PLUGIN_PATH[:-1])+'/pyrage/modules'

logging.basicConfig()
instances={}
pluginManager = PluginManager()
pluginManager.setPluginPlaces([PLUGIN_PATH])
pluginManager.collectPlugins()
for plugin in pluginManager.getAllPlugins():
    instances[plugin.name]=plugin.plugin_object