__author__ = 'David Vavra'

import xml.etree.ElementTree as xmlet
from yapsy.PluginManager import PluginManager
import copy

from yapsy import logging


PLUGIN_PATH='/usr/local/lib/python3.3/dist-packages/pyrage/modules/'

class NetworkParser():

    def __init__(self,logger,definitionsFile):
        self.parsedDevices = {}
        self.logger = logger
        self.deviceDef  = None
        self.acls = {}

        """
         instance of currently parsed device, so it's attributes could be accessed
         within the context of methods called by parseDevice method.
        """
        self.currentlyParsedDevice=None

        self.ERR_DEVICE_NOT_FOUND = 1

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


    def parseDevice(self,dev):

        self.currentlyParsedDevice=dev

        deviceInstances = dev.instances
        deviceDef=None
        for device in self.network.iter('device'):
            if device.find('fqdn').text == dev.fqdn:
                deviceDef = device
                break
        if deviceDef is None:
            self.logger.log('warning',"Device '{dev}' not found in xml file.".format(dev=dev.fqdn))
            self.parsedDevices[dev.fqdn] = None
            return self.ERR_DEVICE_NOT_FOUND

        
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
        """ todo, possibly add ipv4 tag into devices.xml """
        dev.ip4=True

        
        dev.groups=deviceDef.attrib['groups'].split(',') if 'groups' in deviceDef.attrib else []

        for member in dev.groups:
            for dev.groups in self.network.iter('group'):
                if dev.groups.attrib['id'] == member:
                    self._parseContext(dev.groups,deviceInstances)

        """ parse the particular device's parameters """
        self._parseContext(deviceDef,deviceInstances)

        self.currentlyParsedDevice=None


    def _parseContext(self,context,instances):
        """
            parses given group and writes it's parameters in object variable.
            Later calls of this or other methods may overwrite those.

            Rules signifancy:
            MEMBER_GROUP (in as-in-file order) < DEVICE
        """
        for name,instance in instances.items():
            instance.parseContext(context)
        return

class Device():
    def __init__(self,deviceName):
        self.instances = copy.deepcopy(instances)

        self.fqdn = deviceName
        self.vendor = ""
        self.type = ""
        self.ip4=False
        self.ip6=False
        self.l2=False
        self.l3=False


logging.basicConfig(level=logging.DEBUG)
instances={}
pluginManager = PluginManager()
pluginManager.setPluginPlaces([PLUGIN_PATH])
pluginManager.collectPlugins()
for plugin in pluginManager.getAllPlugins():
    instances[plugin.name]=plugin.plugin_object