__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin

from pyrage.utils import ErrRequiredData
from pyrage.utils import ErrOptionalData

import re


class SNMP(IPlugin):
    def __init__(self):
        self.communities = None
        self.traps = None
        self.trap_hosts = None
        self.acls = {}

        self.views=None
        self.groups=None
        self.users=None


    def addCommunity(self,id,community,privilege,version='2c',aclId=None):
        if self.communities is None:
            self.communities={}

        if len(id) and version in ['2c','1']:
            self.communities[id] = {}
            self.communities[id]['version'] = version
            self.communities[id]['community'] = community
            if str(privilege).lower() in ['read-only','ro']:
                self.communities[id]['privilege'] = 'RO'
            elif str(privilege).lower() in ['read-write','rw']:
                self.communities[id]['privilege'] = 'RW'
            else:
                raise ErrRequiredData(":snmp:Unsupported community privilege given: '{}'".format(privilege))
            self.communities[id]['aclId'] = aclId

        else:
            if not len(id):
                raise ErrRequiredData(":snmp:Invalid community data given. id:'{0}'".format(id))
            else:
                raise ErrRequiredData(":snmp:Invalid community data given. version:'{0}'".format(version))

    """
        Add trap to a list of categorized traps.

        Category is given as a trap attribute.
    """
    def addTrap(self,trap,tags):
        if self.traps is None:
            self.traps={}
        for tag in tags:
            if tag not in self.traps:
                self.traps[tag] = []
            if trap not in self.traps[tag]:
                self.traps[tag].append(trap)


    def addTrapHost(self,id,auth,version,host,tags,authLevel=None):
        if self.trap_hosts is None:
            self.trap_hosts={}
        if version not in ['1','2c','3']:
            raise ErrRequiredData(":snmp:Invalid snmp version given within trap id '{0}': '{1}'".format(id,version))
        self.trap_hosts[id] = {}
        self.trap_hosts[id]['host'] = host
        self.trap_hosts[id]['auth'] = auth
        self.trap_hosts[id]['tags'] = tags
        self.trap_hosts[id]['version']=version
        self.trap_hosts[id]['authLevel']=authLevel

    def addView(self,viewName,tree,op):
        if self.views is None:
            self.views={}
        if op.lower() not in ['included','excluded']:
            raise ErrRequiredData(":snmp:Invalid snmp view tree type specified, should be one of [included,excluded]: {0}".format(op))
        if viewName not in self.views:
            self.views[viewName]={'included':[],
                                  'excluded':[]}
        self.views[viewName][op.lower()].append(tree)

    def addGroup(self,name,version,aclId,secLevel=None):
        if self.groups is None:
            self.groups={}
        if name not in self.groups:
            if version not in [3]:
                raise ErrRequiredData(":snmp:Invalid group ('{0}') security model specified: '{1}'".format(name,secModel))
            if version=='3' and secLevel.lower() not in ['noauth','auth','priv']:
                raise ErrOptionalData(":snmp:Invalid group ('{0}') authentication level specified: '{1}'".format(name,authLevel))
            group={'version':version,
                   'secLevel':secLevel,
                   'aclId':aclId,
                   'views':{'read':None,'write':None}
                   }
            self.groups[name]=group

    def addViewIntoGroup(self,groupName,viewName,viewPrivilege):
        if viewPrivilege.lower() not in ['read','write']:
            raise ErrRequiredData(":snmp:Invalid view ('{0}') privilege specified: {'1'}".format(viewName,viewPrivilege))
        if groupName not in self.groups:
            raise ErrRequiredData(":snmp:Can't assign view with nonexisting group: '{0}'".format(groupName))
        self.groups[groupName]['views'][viewPrivilege]=viewName

    def addUser(self,userName,group,aclId):
        if self.users is None:
            self.users={}
        if group not in self.groups:
            raise ErrRequiredData(":snmp:Can't assign user '{1}' with nonexisting group: '{0}'".format(group,userName))
        self.users[userName]={
            'group':group,
            'aclId':aclId,
            'auth':None,
            'priv':None
        }

    def changeUserAuth(self,userName,authType,encrypted,authString):
        if userName not in self.users:
            raise ErrRequiredData(":snmp:Can't change v3 authentication type with nonexisting user ('{0}').".format(userName))
        if self.users[userName]['version']!='3':
            raise ErrRequiredData(":snmp:Can't change v3 authentication type with non v3 user ('{0}').".format(userName))
        self.users[userName]['auth']={
            'type':authType,
            'encrypted':True if encrypted else False,
            'authString':authString
        }

    def changeUserPriv(self,userName,privType,encrypted,privString):
        if userName not in self.users:
            raise ErrRequiredData(":snmp:Can't change v3 priv type with nonexisting user ('{0}').".format(userName))
        if self.users[userName]['version']!='3':
            raise ErrRequiredData(":snmp:Can't change v3 authentication type with non v3 user ('{0}').".format(userName))
        self.users[userName]={
            'type':privType,
            'encrypted':True if encrypted else False,
            'privString':privString
        }

    def parseContext(self,context,acls):
        for snmp in context.iter('snmp'):
            for community in snmp.iter('community'):
                aclId = community.attrib['acl_id'] if 'acl_id' in community.attrib else None
                if aclId not in self.acls and aclId is not None:
                    self.acls[aclId]=acls.parseAcl(aclId,4)
                if 'acl6_id' in community.attrib:
                    aclId = community.attrib['acl6_id']
                    if aclId is not None and aclId not in self.acls:
                        self.acls[aclId]=acls.parseAcl(aclId,6)
                self.addCommunity(community.attrib['id'],
                                         community.text,
                                         community.attrib['privilege'],
                                         community.attrib['version'],
                                         aclId
                )

            for trap_host in snmp.iter('trap_host'):
                ver=trap_host.attrib['version']
                self.addTrapHost(
                    id=trap_host.attrib['id'],
                    auth=trap_host.attrib['community'],
                    version=ver,
                    host=trap_host.text,
                    tags=trap_host.attrib['tags'].split(','),
                )

            for trap_host in snmp.iter('trap_host_v3'):

                self.addTrapHost(
                    id=trap_host.attrib['id'],
                    auth=trap_host.attrib['user'],
                    version=3,
                    host=trap_host.text,
                    secLevel=trap_host.attrib['secLevel'],
                    tags=trap_host.attrib['tags'].split(','),
                )

            #authLevel=trap_host.attrib['authLevel'] if ver=='3' else

            for trap in snmp.iter('trap'):
                self.addTrap(trap.text,trap.attrib['tags'].split(','))

            for view in snmp.iter('view'):
                name=view.attrib['id']
                # view is not added if there is no tree defined within it
                for tree in view.iter('tree'):
                    self.addView(
                        name,
                        tree.text,
                        tree.attrib['type'])

            for group in snmp.iter('groupv3'):
                aclId = group.attrib['acl_id'] if 'acl_id' in group.attrib else None
                if aclId is not None and aclId not in self.acls:
                    self.acls[aclId]=acls.parseAcl(aclId,4)
                if 'acl6_id' in group.attrib:
                    aclId = group.attrib['acl6_id']
                    if aclId is not None and aclId not in self.acls:
                        self.acls[aclId]=acls.parseAcl(aclId,6)
                self.addGroup(
                     name=group.attrib['id'],
                     version=3,
                     aclId=aclId,
                     secLevel=group.attrib['secLevel']
                 )
                for view in group.iter('_view'):
                     self.addViewIntoGroup(
                        groupName=group.attrib['id'],
                        viewName=view.text,
                        viewPrivilege=view.attrib['type']
                     )

            for user in snmp.iter('user'):
                aclId = user.attrib['acl_id'] if 'acl_id' in user.attrib else None
                if aclId is not None and aclId not in self.acls:
                    self.acls[aclId]=acls.parseAcl(aclId,4)
                if 'acl6_id' in user.attrib:
                    aclId = user.attrib['acl6_id']
                    if aclId is not None and aclId not in self.acls:
                        self.acls[aclId]=acls.parseAcl(aclId,6)
                self.addUser(
                    userName=user.find('username').text,
                    version='3',
                    group=user.attrib['group'],
                    aclId=aclId
                )
                auth=user.find('auth')
                if len(auth)>0:
                    self.changeUserAuth(
                        userName=user.find('username').text,
                        authType=auth.attrib['type'],
                        encrypted=False if 'encrypted' not in auth.attrib or auth.attrib['encrypted'].lower()=='false' else True,
                        authString=auth.text)
                priv=user.find('priv')
                #def changeUserPriv(self,userName,privType,encrypted,privString)
                if len(priv)>0:
                    self.changeUserPriv(
                        userName=user.find('username').text,
                        privType=auth.attrib['type'],
                        encrypted=False if 'encrypted' not in auth.attrib or auth.attrib['encrypted'].lower()=='false' else True,
                        privString=auth.text
                    )
