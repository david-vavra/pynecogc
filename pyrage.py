# -*- coding: utf-8 -*-
"""
Created on Wed Dec 25 16:19:12 2013

@author: David Vavra
"""


import xml.etree.ElementTree as xmlet
from mako.template import Template
import subprocess
import socket
import sys
import argparse

"""
    Exceptions
"""
class InvalidData(Exception):
    def __init__(self,msg,*data):
        self.msg = msg
        self.data = data

class ErrRequiredData(InvalidData):
    pass

class ErrOptionalData(InvalidData):
    pass

class InvalidVlanRange(ErrRequiredData):
    pass

class InvalidInterface(ErrOptionalData):
    pass

class InvalidAcl(ErrRequiredData):
    pass

class InvalidMask(ErrRequiredData):
    pass

"""
Logging
"""
class Logger():
    def __init__(self,logLevel):
        self.loggingSeverity = {
                            "critical":0,
                            "error":1,
                            "warning":2,
                            "info":3,
                            "debug":4
        }
        self.chosenLogLevel = self.loggingSeverity[logLevel]

    """
        Print given message on stderr output, if its severity is equal or less
        than chosen log level.
    """
    def log(self,msgSeverity,message):
        if msgSeverity not in self.loggingSeverity:
            msgSeverity = "critical"
        if self.loggingSeverity[msgSeverity] <= self.chosenLogLevel:
            sys.stderr.write(msgSeverity.capitalize()+':'+message + "\n")

"""
Supplementary functions
"""
def isValidIP(ip):
    # return boolean value based on whether given argument ip is a valid IP address
    try:
        # first, test if ip is a valid ipv4 addr
        socket.inet_pton(socket.AF_INET,ip)
        return 4
    except socket.error:
        pass
    try:
        # test if ip is a valid ipv6 addr
        socket.inet_pton(socket.AF_INET6,ip)
        return 6
    except socket.error:
        pass
    return False

def buildNetMask(maskLen,wildcardFormat=True):
        try:
            maskLen = int(maskLen)
        except ValueError:
            raise InvalidMask("Invalid mask value given: '{0}'".format(
                maskLen),maskLen)
        if maskLen not in range(33):
            raise InvalidMask("Invalid mask length given: '{0}'".format(
                maskLen),maskLen)

        if wildcardFormat:
            net = '0'
            host = '1'
        else:
            net = '1'
            host = '0'

        net *= maskLen
        host *= (32 - maskLen)

        maskBits = net + host
        maskRepr = {1:{},2:{},3:{},4:{}}

        maskRepr[1]['bits'] = maskBits[0:8][::-1]
        maskRepr[2]['bits'] = maskBits[8:16][::-1]
        maskRepr[3]['bits'] = maskBits[16:24][::-1]
        maskRepr[4]['bits'] = maskBits[24:32][::-1]

        for i in range (8):
            for maskPart in maskRepr:
                if 'num' not in maskRepr[maskPart]:
                    maskRepr[maskPart]['num'] = 0
                maskRepr[maskPart]['num'] += 2**i *int( maskRepr[maskPart]['bits'][i])

        wildcardMask = ""
        for i in maskRepr.keys():
            wildcardMask += str(maskRepr[i]['num']) + "."

        return wildcardMask[:-1]

def validateVlanRange(vlanRangeToValidate):
    """
        Parses given vlan range, supported formats are:
            commas separated list: 1,3,4
            dash separated first and last vlan of the range: 1-4094
    """
    # TODO ? kontrola vlan range (max 4094)?
    # ruzna syntax u jinych vyrobcu?

    vlanRange = []
    isSingleVlan = True

    try:
        int(vlanRangeToValidate)
    except ValueError:
        isSingleVlan = False

    if isSingleVlan: return vlanRange.append(vlanRangeToValidate)

    for commaSepVlan in vlanRangeToValidate.split(','):

        isSingleVlan = True
        try:
            int(commaSepVlan)
        except ValueError:
            isSingleVlan = False

        if isSingleVlan: vlanRange.append(commaSepVlan)
        else:
            dashSepVlan = commaSepVlan.split('-',1)
            isSingleVlan = True
            try:
                int(dashSepVlan[0])
                int(dashSepVlan[1])
            except ValueError as e:
                return False
    return True

def makeListOfVlanRange(vlanRange):
    if not validateVlanRange(vlanRange):
        raise InvalidVlanRange("Invalid vlan range given: {0}".format(vlanRange))
    listOfRanges=vlanRange.split(',')
    vlanList=[]
    for r in listOfRanges:
        if '-' not in r:
            # test whether given ranges are in fact vlans (i.e. vlanRange was sth like '1,2,3,10')
            vlanList.append(int(r))
        else:
            r=r.split('-')
            if len(r)>2:
                # '1-2-10' -> not valid vlanRange
                return []
            try:
                vlanList+=range(int(r[0]),int(r[1])+1)
            except ValueError:
                raise InvalidVlanRange("Invalid vlan range given: {0}".format(vlanRange))
    vlanList.sort()
    return list(set(vlanList))
"""
Classes representing particular configuration aspects of a device
"""
###########################################
###             AAA                     ###
###########################################
class AAA():
    def __init__(self):
        self.hosts = {}
        self.groups = {}
        self.methodsLists={}

    def addMethodList(self,listName,types,methods):
        if not len(listName)>0 or not len(types)>0 or not len(methods)>0:
            raise ErrRequiredData("Not enough data given to specify an aaa method list.",listName,types,methods)
        if listName not in self.methodsLists:
            self.methodsLists[listName] = {}
        list = self.methodsLists[listName]
        list['type'] = {}
        for type in types:
            # test if given types dict has good structure
            if isinstance(types[type],str):
                list['type'][type] = types[type]
            else:
                raise ErrRequiredData("Invalid method list type specified. '{0}'".format(types[type]),
                                             types)
        list['methods'] = []
        for method in methods:
            if len(method) > 0:
                list['methods'].append(method)


    def addGroup(self,groupName,groupType):
        if not len(groupName) > 0 or not len(groupType) > 0:
            raise ErrRequiredData("Invald aaa group name or group type specified.",groupName,groupType)

        if groupName not in self.groups:
            self.groups[groupName] = {}
            self.groups[groupName]['hosts'] = []
        group = self.groups[groupName]
        group['type'] = groupType


    def addHost(self,name,host,group,type):
        if not len(name) > 0 or not len(host) > 0:
            raise ErrRequiredData("Invald aaa host id or hostname specified.",name,host)
        if group not in self.groups:
            self.groups[group] = {}
            self.groups[group]['hosts'] = [].append(name)
        else:
            self.groups[group]['hosts'].append(name)
        self.hosts[name] = {}
        self.hosts[name]['ip'] = host
        self.hosts[name]['type'] = type

###########################################
###             ACL                     ###
###########################################
class ACL():

    def __init__(self,aclId):


        self.aclStructure = {'known':['source','destination','action','protocol','established','protocol'],
                             'standard':['source','action'],
                             'extended':['source','destination','action','protocol']}

        self.validAclTypes = ['standard','extended']
        self.aclId = aclId
        self.acl = None

        self.name={}
        self.type={}
        self.rules={}


    def addNames(self,**kwargs):
        for key,value in kwargs.items():
            self.name[key]=value

    def addTypes(self,**kwargs):
        for key,value in kwargs.items():
            self.type[key]=value

    def addRule(self,id,rule):
        assert rule and id
        self.rules[id]=rule

class ACLv4(ACL):
    pass
class ACLv6(ACL):
    pass


###########################################
###             Arp inspection          ###
###########################################
class ArpInspection():
    def __init__(self):
        self.trustedPorts = []
        self.vlanRange = ""

    def addTrustedInt(self,trustedInterface):
        if trustedInterface is None:
            raise InvalidInterface(
                ":arp_inspection:Invalid arp inspection trusted interface specified: '{0}'".format(trustedInterface),
                trustedInterface)
        else:
            self.trustedPorts.append(trustedInterface)


    def addVlanRange(self,vlanRange):
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":arp_inspection:Invalid arp inspection vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange

###########################################
###             DHCP Snooping           ###
###########################################
class DHCPSnooping():
    def __init__(self):
        self.trustedPorts = []
        self.vlanRange = ""

    def addTrustedInt(self,trustedInterface):
        if trustedInterface is None:
            raise InvalidInterface(
                ":dhcp_snooping:Invalid dhcp snooping trusted interface specified: '{0}'".format(trustedInterface),
                trustedInterface)
        else:
            self.trustedPorts.append(trustedInterface)

    def addVlanRange(self,vlanRange):
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":dhcp_snooping:Invalid dhcp snooping vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanRange = vlanRange

###########################################
###             DNS                     ###
###########################################

class DNS():
    def __init__(self):
        self.hosts = {}

    def addHost(self,id,host):
        self.hosts[id] = host
        return 0

###########################################
###             IP Source Guard         ###
###########################################

class InvalidVlanRange(ErrRequiredData):
    pass

class IPSourceGuard():
    def __init__(self):
        self.vlanList=[]

    def addVlanRange(self,vlanRange):
        if not validateVlanRange(vlanRange):
            raise InvalidVlanRange(":ip_source_guard:Invalid IP source guard vlan range given: '{0}'".format(vlanRange),
                                   vlanRange)
        else:
            self.vlanList = makeListOfVlanRange(vlanRange)

###########################################
###             NTP                     ###
###########################################
class NTP():
    def __init__(self):
        self.hosts = {}
        self.acl = None

    def addAcl(self,aclId,acl):
        self.acl = acl
        return 0

    def addHost(self,id,host):
        if id not in self.hosts:
            self.hosts[id] = host
        return 0


###########################################
###             SNMP                    ###
###########################################
class SNMP():
    def __init__(self):
        self.communities = {}
        self.traps = {}
        self.trap_hosts = {}
        self.acls = {}

        self.views={}
        self.groups={}
        self.users={}


    def addCommunity(self,id,community,privilege,version='2c',aclId=None,acl=None):
        if len(id) and version in ['2c','1']:
            self.communities[id] = {}
            self.communities[id]['community'] = community
            if str(privilege).lower() in ['read-only','ro']:
                self.communities[id]['privilege'] = 'RO'
            elif str(privilege).lower() in ['read-write','rw']:
                self.communities[id]['privilege'] = 'RW'
            else:
                raise ErrRequiredData(":snmp:Unsupported privilege given: '{}'".format(privilege))
            self.communities[id]['version'] = version
            if aclId is not None and aclId not in self.acls and acl is not None:
                self.acls[aclId] = acl
                self.communities[id]['acl_id'] = aclId
            elif aclId in self.acls:
                self.communities[id]['acl_id'] = aclId

            return  0

        else:
            #self.logger.log("warning","SNMP: Unable to parse following: id:'{0}', privilege'{1}', version:'{3}', community:'{4}'".format(id,privilege,version,community))
            if not len(id):
                raise ErrRequiredData(":snmp:Invalid community data given. id:'{0}'".format(id))
            else:
                raise ErrRequiredData(":snmp:Invalid community data given. version:'{0}'".format(version))

    """
        Add trap to a list of categorized traps.

        Category is given as a trap attribute.
    """
    def addTrap(self,trap,tags):
        for tag in tags:
            if tag not in self.traps:
                self.traps[tag] = []
            if trap not in self.traps[tag]:
                self.traps[tag].append(trap)


    def addTrapHost(self,id,auth,version,host,tags,authLevel=None):
        if version not in ['1','2c','3']:
            raise ErrRequiredData(":snmp:Invalid snmp version given within trap id '{0}': '{1}'".format(id,version))
        self.trap_hosts[id] = {}
        self.trap_hosts[id]['host'] = host
        self.trap_hosts[id]['auth'] = auth
        self.trap_hosts[id]['tags'] = tags
        self.trap_hosts[id]['version']=version
        self.trap_hosts[id]['authLevel']=authLevel

    def addView(self,viewName,tree,op):
        if op.lower() not in ['included','excluded']:
            raise ErrRequiredData(":snmp:Invalid snmp view tree type specified, should be one of [included,excluded]: {0}".format(op))
        if viewName not in self.views:
            self.views[viewName]={'included':[],
                                  'excluded':[]}
        self.views[viewName][op.lower()].append(tree)

    def addGroup(self,name,secModel,aclId,authLevel=None):
        if name not in self.groups:
            if secModel.lower() not in ['1','2c','3']:
                raise ErrRequiredData(":snmp:Invalid group ('{0}') security model specified: '{1}'".format(name,secModel))
            if secModel=='3' and authLevel.lower() not in ['noauth','auth','priv']:
                raise ErrOptionalData(":snmp:Invalid group ('{0}') authentication level specified: '{1}'".format(name,authLevel))
            group={'secModel':secModel,
                   'authLevel':authLevel,
                   'aclId':aclId,
                   'views':{'read':[],'write':[]}
                   }
            self.groups[name]=group

    def addViewIntoGroup(self,groupName,viewName,viewPrivilege):
        if viewPrivilege.lower() not in ['read','write']:
            raise ErrRequiredData(":snmp:Invalid view ('{0}') privilege specified: {'1'}".format(viewName,viewPrivilege))
        if groupName not in self.groups:
            raise ErrRequiredData(":snmp:Can't assign view with nonexisting group: '{0}'".format(groupName))
        self.groups[groupName]['views'][viewPrivilege].append(viewName)

    def addUser(self,userName,group,version,acl):
        if version.lower() not in ['1','2c','3']:
            raise ErrRequiredData(":snmp:Invalid user ('{0}') snmp version specified: '{1}'".format(userName,version))
        if group not in self.groups:
            raise ErrRequiredData(":snmp:Can't assign user '{1}' with nonexisting group: '{0}'".format(group,userName))
        self.users[userName]={
            'group':group,
            'version':version,
            'aclId':acl,
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

###########################################
###             Syslog                  ###
###########################################

class Syslog():
    def __init__(self):
        self.hosts={}
        self.facility=""
        self.severity=""
        # validate facilities
        # validate emergency

    def addServer(self,id,host):
        if len(host)>0 and id is not None:
            self.servers[id]=host


    def changeFacility(self,facility):
        self.facility=facility
        return 0

    def changeSeverity(self,severity):
        self.severity=severity
        return 0
###########################################
###             uRPF                    ###
###########################################
class URPF():
    def __init__(self):
        # mode:[ints]
        self.interfaces={}
        self.defaultMode=None
        self.validModes=['strict','loose']

    def addInterface(self,int,mode):
        if mode.lower() not in self.validModes:
            raise ErrOptionalData(":urpf:Skipping. Invalid mode specified for interface '{int}: '{mode}''".format(
                mode=mode,
                int=int
            ))

    def changeDefaultMode(self,mode):
        if mode.lower() not in self.validModes:
            raise ErrOptionalData(":urpf:Invalid default mode specified: '{0}'".format(
                mode
            ))
        self.defaultMode=mode

###########################################
###             VTY                     ###
###########################################
class VTY():
    def __init__(self):
        self.acl_v4=None
        self.acl_v6=None
        self.protocols = {}
        self.vlanNumber = 1
        self.gateway = ""

        self.gatewaySyntax = {
            'cisco':'ip default-gateway {0}',
            'comware':''
        }

        self.separator = {
            'cisco':'!'
        }

    def addProtocol(self,protocol,version=2,timeout=120,retries=3):
        if protocol not in self.protocols:
            self.protocols[protocol] = {}
            if version is not None:
                self.protocols[protocol]['version'] = version
            self.protocols[protocol]['timeout'] = timeout
            self.protocols[protocol]['retries'] = retries

    def addAcl(self,aclId,aclInstance):
        if aclInstance.__class__.__name__[-2:]=='v4':
            self.acl_v4 = aclInstance
        else:
            self.acl_v6=aclInstance

    def addGateway(self,gateway):
        if not isValidIP(gateway):
            raise ErrRequiredData(
                    "Invalid gateway IP address given: {0}".format(gateway),
                    gateway
            )

        self.gateway = gateway
        return 0

    def addVlan(self,vlan):
        try:
            if int(vlan) > 0 and int(vlan) < 4096:
                self.vlanNumber = vlan
        except ValueError as e:
            raise ErrRequiredData(":vty:Invalid vlan identifier specified: '{0}'".format(vlan),vlan)



class NetworkParser():
    
    def __init__(self,logger,definitionsFile):
        self.parsedDevices = {}
        self.logger = logger
        self.deviceDef  = None
        self.acls = {}

        # instance of currently parsed device, so it's attributes could be accessed
        # within the context of methods called by parseDevice method.
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

        deviceInstances = dev.getInstances()
        deviceDef=None
        for device in self.network.iter('device'):
            if device.find('fqdn').text == dev.fqdn:
                deviceDef = device
                break
        if deviceDef is None:
            self.logger.log('warning',"Device '{dev}' not found in xml file.".format(dev=dev.fqdn))
            self.parsedDevices[dev.fqdn] = None
            return self.ERR_DEVICE_NOT_FOUND

        # todo mozne chyby pri zpracovani exception, or [OK,list]

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
        # todo, possibly add ipv4 tag into devices.xml
        dev.ip4=True

        # parse group info starting with the DEFAULT group and then with the
        # other groups in the same order as they are defined within the xml.
        """
        for group in self.network.iter('group'):
            if group.attrib['id'] == 'DEFAULT':
                self._parseContext(group,deviceInstances)
        """
        dev.groups=deviceDef.attrib['groups'].split(',') if 'groups' in deviceDef.attrib else []

        for member in dev.groups:
            for dev.groups in self.network.iter('group'):
                if dev.groups.attrib['id'] == member:
                    self._parseContext(dev.groups,deviceInstances)

        # parse the particular device's parameters
        self._parseContext(deviceDef,deviceInstances)

        self.currentlyParsedDevice=None


    def _parseContext(self,context,instances):
        """
            parses given group and writes it's parameters in object variable.
            Later calls of this or other methods may overwrite those. 

            Rules signifancy:            
            DEFAULT_GROUP < MEMBER_GROUP < DEVICE
        """


        for snmpSection in context.iter('snmp_'):
            try:
                self._parseSnmp(snmpSection,instances['snmp'])
            except ErrRequiredData as e:
                    self.logger.log('error',self.currentlyParsedDevice.fqdn+':snmp:'+e.msg)

        for snmpSection in context.iter('snmp'):
            try:
                self._parseSnmp(snmpSection,instances['snmp'])
            except ErrRequiredData as e:
                    self.logger.log('error',self.currentlyParsedDevice.fqdn+':snmp:'+e.msg)

        for aaa_def in context.iter('aaa'):
             self._parseAAA(aaa_def,instances['aaa'])

        for dns in context.iter('dns_host'):
            self._parseDNS(dns,instances['dns'])

        for ntp in context.iter('ntp'):
            self._parseNtp(ntp,instances['ntp'])

        for vty in context.iter('vty'):
            self._parseVty(vty,instances['vty'])

        for dhcp in context.iter('dhcp_snooping'):
            self._parseDHCPSnooping(dhcp,instances['dhcpSnooping'])

        for arp in context.iter('arp_inspection'):
            self._parseArpInspection(arp,instances['arpInspection'])

        for syslog in context.iter('syslog'):
            self._parseSyslog(syslog,instances['syslog'])

        for urpf in context.iter('urpf'):
            self._parseURPF(urpf,instances['uRPF'])

        for ipsg in context.iter('ip_source_guard'):
            self._parseIPSourceGuard(ipsg,instances['ipSourceGuard'])

        # todo errdisable parsing
        for errdisable in context.iter('errdisable'):
            pass


    def _parseSyslog(self,contextToParse,syslogInstance):
        syslogInstance=Syslog()
        if 'severity' in contextToParse.attrib:
            syslogInstance.changeSeverity(contextToParse.attrib['severity'])
        if 'facility' in contextToParse.attrib:
            syslogInstance.changeSeverity(contextToParse.attrib['facility'])
        for host in contextToParse.iter('syslog_host'):
            syslogInstance.addServer(
                host.attrib['id'],
                host.text
            )

    def _parseAAA(self,contextToParse,aaaInstance):
        # todo vyresit key errors
        for group in contextToParse.iter('aaa_group'):
            aaaInstance.addGroup(
                    group.attrib['id'],
                    group.attrib['type']
            )

        for host in contextToParse.iter('aaa_host'):
            if 'group' not in host.attrib:
                hostGroup = 'DEFAULT'
            else:
                hostGroup = host.attrib['group']
            aaaInstance.addHost(
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
            aaaInstance.addMethodList(
                list.attrib['name'],
                types,
                methods
            )
        return 0

    def _parseDNS(self,contextToParse,dnsInstance):

        for dnsServer in contextToParse.iter('dns_host'):
            dnsInstance.addHost(dnsServer.attrib['id'],dnsServer.text)

    def _parseNtp(self,contextToParse,instance):
        if 'acl_id' in contextToParse.attrib:
            aclId = contextToParse.attrib['acl_id']
            if aclId not in self.acls:
                acl = ACLv4(aclId)
                self._parseAcl(self.network,acl)
                instance.addAcl(aclId,acl)
                self.acls[aclId] = acl
            else:
                instance.addAcl(aclId,self.acls[aclId])

        for ntpServer in contextToParse.iter('host'):
            # TODO validate ip address of the server
            instance.addHost(ntpServer.attrib['id'],ntpServer.text)
        return 0

    def _parseSnmp(self,snmp,instance):

        """
            Parse snmp related information from group definition. 
            
            It consists of three groups: 
                snmp communities
                host to which traps are sent
                traps itself

            <snmp>
                <trap_host id="1" tags="all,auth" community="UVTtrap">thingol</trap_host>
                <trap tags="auth">aaa_server</trap>
                <trap tags="auth,all">authenticate-fail</trap>
                <community version="2c" id="backup" privilege="read-write" acl_id="uvt_vty_snmp">private</community>
	            <community version="2c" id="ip-mac-port" privilege="read-only" acl_id="UVT_RW">public</community>
            </snmp>
        """
        """
            Test whether we are about to parse the old way of snmp definition within the device scope.

            <snmp version="2c" id="ip-mac-port" privilege="read-only">public</snmp>

        """
        if snmp.text is not None and snmp.tag == 'snmp' and all(k in snmp.attrib for k in ['version','id','privilege']):
            instance.addCommunity(snmp.attrib['id'],snmp.text,
                                     snmp.attrib['privilege'],
                                     snmp.attrib['version'])

        else:
            for community in snmp.iter('community'):
                aclId = community.attrib['acl_id']
                if aclId not in self.acls:
                    acl = ACLv4(aclId)
                    self._parseAcl(self.network,acl)
                    self.acls[aclId] = acl
                try:
                    instance.addCommunity(community.attrib['id'],
                                         community.text,
                                         community.attrib['privilege'],
                                         community.attrib['version'],
                                         aclId,
                                         self.acls[aclId])
                except ErrOptionalData as e:
                    self.logger.log('warning',self.currentlyParsedDevice.fqdn+':snmp:'+e.msg)

            for trap_host in snmp.iter('trap_host'):
                ver=trap_host.attrib['version']
                instance.addTrapHost(
                    id=trap_host.attrib['id'],
                    auth=trap_host.attrib[
                        'user' if ver=='3' else 'community'
                    ],
                    version=ver,
                    host=trap_host.text,
                    tags=trap_host.attrib['tags'].split(','),
                    authLevel=trap_host.attrib['authLevel'] if ver=='3' else None
                )

            for trap in snmp.iter('trap'):
                instance.addTrap(trap.text,trap.attrib['tags'].split(','))

            for view in snmp.iter('view'):
                name=view.attrib['id']
                # view is not added if there is no tree defined within it
                for tree in view.iter('tree'):
                    instance.addView(
                        name,
                        tree.text,
                        tree.attrib['type'])

            for group in snmp.iter('group'):
                 instance.addGroup(
                     name=group.attrib['id'],
                     secModel=group.attrib['secModel'],
                     aclId=group.attrib['acl'],
                     authLevel=group.attrib['authLevel'] if group.attrib['secModel']=='3' else None
                 )
                 for view in group.iter('_view'):
                     instance.addViewIntoGroup(
                        groupName=group.attrib['id'],
                        viewName=view.text,
                        viewPrivilege=view.attrib['type']
                     )

            for user in snmp.iter('user'):
                if user.attrib['version']=='3':
                    instance.addUser(
                        userName=user.find('username').text,
                        version='3',
                        group=user.attrib['group'],
                        acl=user.attrib['acl']
                    )
                    auth=user.find('auth')
                    if len(auth)>0:
                        instance.changeUserAuth(
                            userName=user.find('username').text,
                            authType=auth.attrib['type'],
                            encrypted=False if 'encrypted' not in auth.attrib or auth.attrib['encrypted'].lower()=='false' else True,
                            authString=auth.text)
                    priv=user.find('priv')
                    #def changeUserPriv(self,userName,privType,encrypted,privString)
                    if len(priv)>0:
                        instance.changeUserPriv(
                            userName=user.find('username').text,
                            privType=auth.attrib['type'],
                            encrypted=False if 'encrypted' not in auth.attrib or auth.attrib['encrypted'].lower()=='false' else True,
                            privString=auth.text
                        )

    def _parseVty(self,contextToParse,instance):

        # Parse desired transport protocol and its parameters. 
        protocol = contextToParse.find('protocol')
        if protocol is not None:
            if protocol.text == 'ssh':
                if  'version' in protocol.attrib and 'timeout' in protocol.attrib and 'retries' in protocol.attrib:
                    version = protocol.attrib['version']
                    timeout = protocol.attrib['timeout']
                    retries = protocol.attrib['retries']
                    instance.addProtocol(protocol.text,version,timeout,retries)
                else:
                    instance.addProtocol(protocol.text)
        # Parse id of acl used to limit access to device's vty
        if contextToParse.find('acl_id') is not None:
            aclId = contextToParse.find('acl_id').text
            if aclId not in self.acls:
                acl = ACLv4(aclId)
                self._parseAcl(self.network,acl)
                instance.addAcl(aclId,acl)
                self.acls[aclId] = acl
            else:
                instance.addAcl(aclId,self.acls[aclId])

        # parse num of mgmt vlan
        if contextToParse.find('vty_vlan') is not None:
            # TODO vlan validation TODO, maybe should be made when validating parsed information within a generator class
            instance.addVlan(contextToParse.find('vty_vlan').text)
        
        if contextToParse.find('vty_gw') is not None:
            # TODO ip address validation
            instance.addGateway(contextToParse.find('vty_gw').text)

        return 0

    def _parseDHCPSnooping(self,contextToParse,dhcpSnoopingInstance):
        vlanRange = contextToParse.find('vlan_range')
        if vlanRange is not None:
            try:
                dhcpSnoopingInstance.addVlanRange(vlanRange.text)
            except ErrRequiredData as e:
                self.logger.log('error',e.message)
            except ErrOptionalData as e:
                self.logger.log('warning',e.message)

        for interface in contextToParse.iter('trusted_interface'):
            try:
                dhcpSnoopingInstance.addTrustedInt(interface.text)
            except ErrRequiredData as e:
                self.logger.log('error',e.message)
            except ErrOptionalData as e:
                self.logger.log('warning',e.message)

    def _parseArpInspection(self,contextToParse,arpInspectionInstance):
        vlanRange = contextToParse.find('vlan_range')
        if vlanRange is not None:
            try:
                arpInspectionInstance.addVlanRange(vlanRange.text)
            except ErrRequiredData as e:
                self.logger.log('error',e.message)
            except ErrOptionalData as e:
                self.logger.log('warning',e.message)
        for interface in contextToParse.iter('trusted_interface'):
            try:
                arpInspectionInstance.addTrustedInt(interface.text)
            except ErrRequiredData as e:
                self.logger.log('error',e.message)
            except ErrOptionalData as e:
                self.logger.log('warning',e.message)

    # TODO
    def _parseErrdisableRecovery(self,contextToParse,instance):
        return 0
    def _parseAcl(self,context,instance):
        aclId = instance.aclId
        found = False
        for acl in context.iter('aclv4'):
            if 'id' in acl.attrib:
                if aclId == acl.attrib['id']:
                    found = True
                    break
        # todo print err
        if not found:
            raise Exception("Acl '%s' is not defined in the given context!" % aclId)
        # add the acl name(s)
        aclNames={}
        for aclName in acl.iter('name'):
            if 'id' not in aclName.attrib:
                aclNames['generic'] = aclName.text
            else: aclNames[aclName.attrib['id']] = aclName.text
        instance.addNames(**aclNames)

        aclTypes={}
        for aclType in acl.iter('type'):
            if 'id' not in aclType.attrib:
                aclTypes['generic'] = aclType.text
            else: aclTypes[aclType.attrib['id']] = aclType.text
        instance.addTypes(**aclTypes)


        for rule in acl.iter('rule'):
            aclLine={}
            rule_id = rule.attrib['seq']
            if 'optional' in rule.attrib:
                if rule.attrib['optional'].lower() in ['true','false']:
                    aclLine['optional']= True if rule.attrib['optional'].lower()=='true' else False
            for children in rule:
                aclLine[children.tag] = children.text
                if children.tag in ['source','destination']:
                    aclLine[children.tag+'_ip'] = children.text
                    for attrib in children.attrib:
                        aclLine[children.tag+"_"+attrib] = children.attrib[attrib]
                if children.tag == 'action':
                    if 'log' in children.attrib and children.attrib['log'] == 'True':
                        aclLine['log'] = 'log'
                if children.tag == 'protocol':
                    if 'state' in children.attrib:
                        aclLine['state'] = children.attrib['state']
            instance.addRule(rule_id,aclLine)


    def _parseURPF(self,context,instance):
        if 'type' not in context.attrib:
            self.logger.log('error',"{dev}: {feature}: Interface does not have uRPF mode specified!".format(
                dev=self.currentlyParsedDevice.fqdn,
                feature='uRPF'
            ))
        try:
            if context.text.lower()=='default':
                instance.changeDefaultMode(context.attrib['type'])
            else:
                instance.addInterface(context.text,context.attrib['type'])
        except ErrOptionalData as e:
            self.logger.log('warning',"{dev}: {feature}: ".format(
                dev=self.currentlyParsedDevice.fqdn,
                feature='uRPF'
            )+e.message)
        except ErrRequiredData as e:
            self.logger.log('error',"{dev}: {feature}: ".format(
                dev=self.currentlyParsedDevice.fqdn,
                feature='uRPF'
            )+e.message)

    def _parseIPSourceGuard(self,context,instance):
        if context.find('vlan_range') is not None:
             instance.addVlanRange(context.find('vlan_range').text)

class Device():
    def __init__(self,deviceName):
        self.instances = {
              'snmp':SNMP(),
              'dhcpSnooping':DHCPSnooping(),
              'arpInspection':ArpInspection(),
              'aaa':AAA(),
              'dns':DNS(),
              'ntp':NTP(),
              'vty':VTY(),
              #'errdisable':Errdisable(),
              'syslog':Syslog(),
              'uRPF':URPF(),
              'ipSourceGuard':IPSourceGuard()
            }
        self.fqdn = deviceName
        self.vendor = ""
        self.type = ""
        self.ip4=False
        self.ip6=False

    def getInstances(self):
        return self.instances



def main():

    #
    # handle input args
    #
    argParser=argparse.ArgumentParser(description="Wrapper for router audit tool ncat.")
    argParser.add_argument('-t','--configType',help="Chooses the directory with configuration files for given audit among the others in ncat config dir")
    argParser.add_argument('-r','--rulesFile_template', help="Name of the mako template file in directory chosen with the -t option")
    argParser.add_argument('-n','--networkDef', help="Location of the network definition XML file")
    argParser.add_argument('device_cfg',nargs='+')
    inputArgs=argParser.parse_args(sys.argv[1:])

    logger = Logger('warning')

    #
    # try to parse xml file
    #
    parser = NetworkParser(logger,inputArgs.networkDef)
    deviceInstances={}
    for dev in inputArgs.device_cfg:
        deviceInstances[dev]=Device(dev)
        try:
            parser.parseDevice(deviceInstances[dev])
        except InvalidData as e:
            logger.log('error',dev+e.msg)
            raise SystemExit(1)

    #
    # generate ncat rules for every device
    #

    mkt=Template(open(inputArgs.rulesFile_template).read())
    for dev,instance in deviceInstances.items():
        f=open('{0}.rules'.format(dev),'w')
        f.write(mkt.render(
            device=instance,
            bgp=True,
            ospf=True,
            hsrp=True,
            **instance.instances))
        f.close()

    #
    # launch ncat for every device
    #
    ncatOutputFilesString=[]
    allRules=""
    for dev,instance in deviceInstances.items():
        try:
            subprocess.check_call(['ncat',
                         '-t={0}'.format(inputArgs.configType),
                         '-r={0}'.format(dev+'.rules'),
                         dev])
        except subprocess.CalledProcessError as e:
            raise SystemExit(e.returncode)
        ncatOutputFilesString.append(dev+'.ncat_out.txt')
        allRules+=dev+'.rules,'

    try:
        subprocess.check_call(['ncat_report',
                         '-t={0}'.format(inputArgs.configType),
                         '-r={0}'.format(allRules[:-1]),
                         ]+(ncatOutputFilesString))

    except subprocess.CalledProcessError as e:
            raise SystemExit(e.returncode)

if __name__=="__main__":
    main()
      
