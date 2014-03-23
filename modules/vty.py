__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin
from pyrage.acl import ACLv4
from pyrage.utils import isValidIP
from pyrage.utils import ErrRequiredData
import pyrage.utils

class VTY(IPlugin):
    def __init__(self):
        self.acl=None
        self.acl6=None
        self.protocols = {}
        self.vlan = 1
        self.gw = ""


    def _addProtocol(self,protocol,version=2,timeout=600,retries=3):
        if protocol not in self.protocols:
            self.protocols[protocol] = {}
            if version is not None:
                self.protocols[protocol]['version'] = version
            self.protocols[protocol]['timeout'] = timeout
            self.protocols[protocol]['retries'] = retries

    def _addAcl(self,aclId,aclInstance,ver):
        if ver==4:
            self.acl = aclInstance
        elif ver==6:
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
            if int(vlan) >= pyrage.utils.VLAN_MIN and int(vlan) <= pyrage.amber.VLAN_MAX:
                self.vlan = vlan
        except ValueError as e:
            raise ErrRequiredData(
                "vty:Invalid vlan identifier specified: '{0}'".format(vlan),
                vlan)


    def parseContext(self,contextToParse,acls):

        for vty in contextToParse.iter('vty'):
            # Parse desired transport protocol and its parameters.
            protocol = contextToParse.find('protocol')
            if protocol is not None:
                if protocol.text == 'ssh':
                    sshParams={}
                    if 'version' in protocol.attrib:
                        version = protocol.attrib['version']
                    if 'timeout' in protocol.attrib:
                        timeout = protocol.attrib['timeout']
                    if 'retries' in protocol.attrib:
                        retries = protocol.attrib['retries']
                    self._addProtocol(protocol.text,**sshParams)
                else:
                    self._addProtocol(protocol.text)
            # Parse id of acl used to limit access to device's vty
            if contextToParse.find('acl_id') is not None:
                aclId = contextToParse.find('acl_id').text
                acl=acls.parseAcl(aclId,4)
                self._addAcl(aclId,acl)

            if contextToParse.find('acl6_id') is not None:
                aclId = contextToParse.find('acl6_id').text
                acl=acls.parseAcl(aclId,6)
                self._addAcl(aclId,acl)

            if contextToParse.find('vlan') is not None:
                self._addVlan(contextToParse.find('vty_vlan').text)

            if contextToParse.find('gw') is not None:
                self._addGateway(contextToParse.find('gw').text)

