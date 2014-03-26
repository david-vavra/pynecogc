__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin
# zmenit po testovani
from pyrage.utils import validateVlanRange
from pyrage.utils import InvalidVlanRange
from pyrage.utils import InvalidInterface



class DHCPSnooping(IPlugin):
    def __init__(self):
        self.trustedPorts = None
        self.vlanRange = None

    def addTrustedInt(self,trustedInterface):

        if trustedInterface is None:
            raise InvalidInterface(
                ":dhcp_snooping:Invalid dhcp snooping trusted interface specified: '{0}'".format(trustedInterface),
                trustedInterface)
        else:
            if self.trustedPorts is None:
                self.trustedPorts=[]
            self.trustedPorts.append(trustedInterface)

    def addVlanRange(self,vlanRange):
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":dhcp_snooping:Invalid dhcp snooping vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange

    def parseContext(self,contextToParse):
        for dhcp in contextToParse.iter('dhcp_snooping'):
            vlanRange = dhcp.find('vlan_range')
            if vlanRange is not None:
                self.addVlanRange(vlanRange.text)

            for interface in dhcp.iter('trusted_interface'):
                self.addTrustedInt(interface.text)



