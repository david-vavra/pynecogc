__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin
from pyrage.acl import ACLv4
from pyrage.acl import ACLv6
from utils import ErrOptionalData


class NTP(IPlugin):
    def __init__(self):
        self.hosts = None
        self.acl = None
        self.acl6 = None

    def _addAcl(self,aclId,acl):
        if type(acl)==type(ACLv4):
            self.acl = acl
        elif type(acl)==type(ACLv6):
            self.acl6=acl
        else:
            raise ErrOptionalData("ntp:Unable to add ACL, invalid instance: {0}".format(type(acl)))
    def _addHost(self,id,host):
        self.hosts={}
        if id not in self.hosts:
            self.hosts[id] = host

    def parseContext(self,context,acls):
        contextToParse=context
        for ntp in context.iter('ntp'):
            for acl in contextToParse.iter('acl_id'):
                aclId=acl.text
                acl=acls.parseAcl(aclId,4)
                self._addAcl(aclId,acl)

            for acl in contextToParse.iter('acl6_id'):
                aclId=acl.text
                acl=acls.parseAcl(aclId,6)
                self._addAcl(aclId,acl)

            for ntpServer in contextToParse.iter('host'):
                self.addHost(ntpServer.attrib['id'],ntpServer.text)