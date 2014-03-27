__author__ = 'David Vavra'

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
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":arp_inspection:Invalid arp inspection vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange


    def parseContext(self,contextToParse,*args):
        for arp in contextToParse.iter('arp_inspection'):
            arpInspectionInstance=self
            vlanRange = contextToParse.find('vlan_range')
            if vlanRange is not None:
                arpInspectionInstance.addVlanRange(vlanRange.text)
            for interface in contextToParse.iter('trusted_interface'):
                arpInspectionInstance.addTrustedInt(interface.text)


