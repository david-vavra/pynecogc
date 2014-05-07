__author__ = 'David Vavra'

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


