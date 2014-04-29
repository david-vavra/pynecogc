__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin
from pyrage.acl import ACLv4
from pyrage.acl import ACLv6
from pyrage.utils import ErrOptionalData


class NTP(IPlugin):
    def __init__(self):
        self.hosts = None
        self.acls = {'peer':None,
                     'server':None,
                     'query':None,
                     'sync':None
        }
        self.acls6 = {'peer':None,
                     'server':None,
                     'query':None,
                     'sync':None
        }
    def _addAcl(self,aclId,acl,ntpAccess):
        if ntpAccess not in ['peer','server','query','sync']:
            raise ErrOptionalData(":ntp:Unable to add ACL, invalid access level specified: {0}".format(ntpAccess))
        if isinstance(acl,ACLv4):
            self.acls[ntpAccess] = acl
        elif isinstance(acl,ACLv6):
            self.acls6[ntpAccess]=acl
        else:
            raise ErrOptionalData(":ntp:Unable to add ACL ({1}), invalid instance: {0}".format(type(acl),aclId))
    def _addHost(self,id,host):
        if self.hosts is None:
            self.hosts = {}
        if id not in self.hosts:
            self.hosts[id] = host

    def parseContext(self,context,acls):
        contextToParse=context
        for ntp in context.iter('ntp'):
            for acl_id in ntp.iter('acl_id'):
                aclId=acl_id.text
                try:
                    acl=acls.parseAcl(aclId,4)
                except ErrOptionalData as e:
                    e.message=':ntp'+e.message
                    raise
                ntpAccess=None
                if 'access' in acl_id.attrib:
                    ntpAccess=acl_id.attrib['access']
                self._addAcl(aclId,acl,ntpAccess)

            for acl_id in ntp.iter('acl6_id'):
                aclId=acl_id.text
                ntpAccess=None
                if 'access' in acl_id.attrib:
                    ntpAccess=acl_id.attrib['access']
                try:
                    acl=acls.parseAcl(aclId,6)
                except ErrOptionalData as e:
                    e.message=':ntp'+e.message
                    raise
                self._addAcl(aclId,acl,ntpAccess)

            for ntpServer in ntp.iter('host'):
                self._addHost(ntpServer.attrib['id'],ntpServer.text)