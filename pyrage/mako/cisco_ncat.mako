## -*- coding: utf-8 -*-

<%page args="dhcpSnooping=None,arpInspection=None, uRPF=None, ipSourceGuard=None, syslog=None, ntp=None, bgp=None, ospf=None, hsrp=None, vty=None,device=None,aaa=None,snmp=None, **kwargs"/>

# FUNCTIONS
<%def name="makeRegexOfContextInstanceList(contextList)">\
${'('+('|'.join(list(map(lambda x: '^'+str(x)+'$',contextList))))+')'}\
</%def>

<%def name="makeNegRegexOfContextInstanceList(contextList)">\
${'(?!('+('|'.join(list(map(lambda x: '^'+str(x)+'$',contextList))))+').+)'}\
</%def>

<%!
def makeListOfVlanRange(vlanRange):
    if not vlanRange:
        return ['ERR']
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
                return ['ERR']
    vlanList.sort()
    return list(set(vlanList))

def fixContextConf(contextName,contextList,conf):
	output=""
	for context in contextList:
		output+="{0} {1}\\\n".format(contextName,
			context)
		output+="{0}\\\n".format(conf)
	return output
	
def newline():
	return '\\\n'
	
from collections import defaultdict 

def buildNetMask(maskLen,wildcardFormat=True):
        try:
            maskLen = int(maskLen)
        except ValueError:
        	return "INVALID_MASK"
            #raise InvalidDataGiven("Invalid mask value given: '{0}'".format(
            #    maskLen),maskLen)
        if maskLen not in range(33):
        	return "INVALID_MASK"
            #raise InvalidDataGiven("Invalid mask length given: '{0}'".format(
            #   maskLen),maskLen)

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
        
from itertools import permutations

def getRegexOfList(values):
    permut=(list(permutations(values)))
    resultingRegex=''
    for p in permut:
        resultingRegex+='('+(''.join(list(p)))+')|'
    return resultingRegex[:-1]

    
    
def makeListOfVlanRange(vlanRange):
#    if not validateVlanRange(vlanRange):
#       return ['ERR']
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
                return ['ERR']
    vlanList.sort()
    return list(set(vlanList))       	
%>

#{{{
#{{{
<%!
import re 

def printAcl(acl):
    validAclTypes = ['standard','extended']
    separator = "!"
    output=""

    if acl is None:
        return "! Unable to print acl\\\n"

 
    # choose the acl name
    name=""
    isNumberedAcl=False
    if 'cisco' in acl.number:
    	name=acl.number['cisco']
    	isNumberedAcl=True
    elif len(acl.name)>0:
        name=acl.name
    else:
        return "! Unable to print acl\\\n"

    #get the acl type
    if 'cisco' in acl.type:
        if acl.type['cisco'] not in ['standard','extended']:
            return "! Unable to print acl: {0}\\\n".format(name)
        else:
            aclType = acl.type['cisco']
    else:
        if 'generic' not in acl.type:
            return "! Unable to print acl: {0}\\\n".format(name)
        elif acl.type['generic'] not in validAclTypes:
            return "! Unable to print acl: {0}\\\n".format(name)
        else:
            aclType = acl.type['generic']

    if len(aclType)==0:
        return "! Unable to print acl: {0}\\\n".format(str(acl.name))

    if aclType == 'standard':
        # standard
        lineSyntax = "%(action)s %(source_ip)s %(source_mask)s"
    else:
        # extended acl
        lineSyntax = "%(action)s %(protocol)s %(source_ip)s %(source_mask)s %(source_port)s %(destination_ip)s %(destination_mask)s %(destination_port)s %(state)s %(log)s"

    lineComment = "remark %(comment)s"
    
    # build the acl
    if not isNumberedAcl:
        output += 'ip access-list {aclType} {name}\\\n'.format(
        	aclType=aclType.lower(), 
        	name=name)
        lineSyntax=' '+lineSyntax

    for lineNum in sorted(acl.rules):
        rule = acl.rules[lineNum]
        # build rule lines
        if 'optional' in rule and rule['optional']:
        	continue
        if 'comment' in rule:
            comment = rule['comment']
            # insert the comment line between the rules,
            # change their seq if neccessary
            if int(lineNum)-1 in acl.rules and not _isAclNumbered(name):
                if int(lineNum)+1 in acl.rules:
                    return "! Unable to print acl: {0}\\\n".format(name)
                else:
                    lineArgs['seq'] = lineNum+1

            # the comment itself
            if isNumberedAcl:
                output += 'access-list {0} '.format(name) + lineComment % rule + '\\\n'
            else:
                output += lineNum + ' ' + lineComment % comment + '\\\n'


        lineArgs = defaultdict(str,rule)
        lineArgs['seq'] = lineNum

        # build wildcard masks from bit-length repr.
        if lineArgs['source_mask']=='32':
        	lineArgs['source_mask']=''
        	lineArgs['source_ip']='host '+lineArgs['source_ip']
        if lineArgs['destination_mask']=='32':
        	lineArgs['destination_mask']=''
        	lineArgs['destination_ip']='host '+lineArgs['destination_ip']
        lineArgs['source_mask'] = "" if  len(lineArgs['source_mask'])==0 else buildNetMask(lineArgs['source_mask'])
        # build a proper source/dest port def.syntax
        lineArgs['source_port']=('eq '+lineArgs['source_port']) if len(lineArgs['source_port']) else lineArgs['source_port']
        lineArgs['destination_port']=('eq '+lineArgs['destination_port']) if len(lineArgs['destination_port']) else lineArgs['destination_port']
        lineArgs['log']='log' if lineArgs['log']==True else '' 
        if aclType != 'standard':
            lineArgs['destination_mask'] = "" if not lineArgs['source_mask'] else buildNetMask(lineArgs['destination_mask'])
        if isNumberedAcl:
            output += 'access-list {0} '.format(name) + (lineSyntax % lineArgs).strip() + '\\\n'
        else:
            output += (lineSyntax % lineArgs).rstrip() + '\\\n'
    
    output=output.replace('deny','deny  ')
    output=output.replace('0.0.0.0 255.255.255.255','any')
    
    return re.sub(r'\\$','',output.strip())
    
def getAclName(acl):
	if acl is None: 
		return ""
	if 'cisco' in acl.number:
		return acl.number['cisco']
	else: 
		return acl.name    
%>
#}}}

<%!
def printAAAServers(aaa):
	# add (.*\n)* or split the definition 
	aaaServers=""
	""" print groups """
	for groupName in aaa.groups:
		group = aaa.groups[groupName]
		aaaServers += "aaa group server {0} {1}\\\n".format(
			group['type'],
			groupName
			)
		
		for hostName in group['hosts']:
			aaaServers += " server name {0}\\\n".format(hostName)

	""" print hosts """
	for hostName in aaa.hosts:
		host = aaa.hosts[hostName]
		if 'ip' in host:
			aaaServers += "{0} server {1}\\\n".format(
				host['type'],
				hostName
			)
			aaaServers += " address ipv4 {0}\\\n".format(
				host['ip']
			)
	return re.sub(r'\\$','',aaaServers.strip())
	
def printAAAServers_old(aaa):
	output=""
	for host in aaa.hosts:
		output+="{1}-server host {0}.*\\\n".format(
			aaa.hosts[host]['ip'],
			aaa.hosts[host]['type'].lower())
	return re.sub(r'\\$','',output.strip())				
%>

<%!
""" SNMP """ 
def printSnmpCommunity(comId,snmp):
	com=snmp.communities[comId]
	if com['version'] == '1' or com['version'] == '2' or com['version'] == '2c':
		community = com['community']
	else:
		return ERR_INVALID_VERSION
	if com['privilege'].lower() in ['read-only','ro']:
		priv = 'RO'
	elif com['privilege'].lower() in ['read-write','rw']:
		priv = 'RW'
	else:
		return ERR_INVALID_PRIV
	if 'aclId' in com:
		if com['aclId'] in snmp.acls:
			aclName = getAclName(snmp.acls['aclId'])
		else:
			aclName="ERR_ACL_FOR_COMMUNITY_NOT_DEFINED"
	else:
		aclName = ""
	return ("snmp-server community %s %s %s" % (
		community,
		priv,
		aclName
	)).strip()

	
	
%>

#}}}

#{{{
# Definition of classes 
ConfigClassName:Selectable
#ConfigClassQuestion:Apply some or all of the rules that are selectable
ConfigClassSelected:Yes
ConfigClassOptional:No
ConfigClassDescription:Root class for all selectable classes/rules/data
ConfigClassParentName:root node

ConfigVersion:0.0.1
ConfigOrganization:Insitute of Computer Science, Masaryk University
ConfigDocumentType:Gold Standard Benchmark
ConfigPlatforms:Cisco IOS devices
ConfigFeedbackTo:vavra@ics.muni.cz
ConfigRulesAlias:cisco-ios-benchmark.html

configintrotext:\
<h2>Introduction</h2>\
<BLOCKQUOTE>\
TODO\
</BLOCKQUOTE>

ConfigTrailingText:Please send a feedback about the benchmark to vavra@ics.muni.cz

#
# A dummy config data value which is needed probably because of a bug in ncat_report.
# It is not further used, so it does not appear in an output though. 
ConfigDataName:DUMMY
ConfigDataQuestion:None
ConfigDataDefaultValue:None
ConfigDataHowToGet:None
ConfigDataDescription:None

ConfigClassName:ICS Level 2 
ConfigClassDescription:Root class for all ICS security requirements of level 2
ConfigClassSelected:Yes
ConfigClassParentName:Selectable

ConfigClassName:1. Management plane 
ConfigClassDescription:Management plane root class
ConfigClassSelected:Yes
ConfigClassParentName:ICS Level 2 

ConfigClassName:2. Control plane 
ConfigClassDescription:Control plane root class
ConfigClassSelected:Yes
ConfigClassParentName:ICS Level 2 

ConfigClassName:3. Data plane 
ConfigClassDescription:Data plane root class
ConfigClassSelected:Yes
ConfigClassParentName:ICS Level 2 

#}}}


###################
#{{{	Data plane
###################

ConfigRuleName:3.1 - Forbid IP source-route
ConfigRuleParentName:3. Data plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>no ip source-route</code>

ConfigRuleName:3.2 Forbid IP directed broadcast
ConfigRuleParentName:3. Data plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>ip directed-broadcast</code>

#{{{DHCP Snooping

% if dhcpSnooping is not None:
ConfigClassName:3.3 DHCP snooping 
ConfigClassDescription:DHCP snooping related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

% if dhcpSnooping.vlanRange is not None:
ConfigRuleName:3.3.1 Require DHCP snooping enabled for specified vlans
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>^ip dhcp snooping vlan (${dhcpSnooping.vlanRange})$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require DHCP snooping enabled
ConfigRuleSelected:Yes
ConfigRuleFix:ip dhcp snooping vlan ${dhcpSnooping.vlanRange}

% else:
ConfigRuleName:3.3.1 Forbid DHCP snooping enabled for any vlans
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ip dhcp snooping vlan</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid DHCP snooping enabled for any vlans
ConfigRuleSelected:Yes
ConfigRuleFix:no ip dhcp snooping vlan
% endif 

% if dhcpSnooping.trustedPorts is not None:
ConfigRuleName:3.3.2 Require chosen DHCP trusted ports
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(dhcpSnooping.trustedPorts)}
ConfigRuleType:Required
ConfigRuleMatch:<code>ip dhcp snooping trust</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require specific ports to be configured as \
DHCP snooping trusted ports 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 ip dhcp snooping trust

# and Forbid any other ports to be trusted 
ConfigRuleName:3.3.3 Forbid any other dhcp snooping trusted ports 
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:${makeNegRegexOfContextInstanceList(dhcpSnooping.trustedPorts)}
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip dhcp snooping trust$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid any other dhcp snooping trusted ports 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip dhcp snooping trust
% else:
ConfigRuleName:3.3.2 Forbid any dhcp snooping trusted ports 
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip dhcp snooping trust$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid any dhcp snooping trusted ports 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip dhcp snooping trust
% endif 
% endif 
#}}}

#{{{ Arp inspection

% if arpInspection is not None:
ConfigClassName:3.4 Arp inspection 
ConfigClassDescription:Arp inspection related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

% if arpInspection.vlanRange is not None:
ConfigRuleName:3.4.1 Require arp inspection enabled
ConfigRuleParentName:3.4 Arp inspection 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>^ip arp inspection vlan ${arpInspection.vlanRange}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require Arp inspection enabled
ConfigRuleSelected:Yes
ConfigRuleFix:ip arp inspection vlan ${arpInspection.vlanRange}
% else:
ConfigRuleName:3.4.1 Forbid arp inspection to be enabled for any vlan
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ip arp inspection vlan</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid DHCP snooping enabled for any vlans
ConfigRuleSelected:Yes
ConfigRuleFix:no ip arp inspection vlan
% endif 

% if arpInspection.trustedPorts is not None: 
ConfigRuleName:3.4.2 Require Arp trusted ports
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(arpInspection.trustedPorts)}
ConfigRuleType:Required
ConfigRuleMatch:<code>^ ip arp inspection trust$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require specific ports to be configured as \
Arp inspection trusted ports
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 ip arp inspection trust

ConfigRuleName:3.4.3 Forbid any other Arp inspection trusted ports
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:${makeNegRegexOfContextInstanceList(arpInspection.trustedPorts)}
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip arp inspection trust$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid any other arp inspection port than those explicitly defined 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip arp inspection trust
% else:
ConfigRuleName:3.4.2 Forbid any Arp inspection trusted ports
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip arp inspection trust$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid any ports to be configured as \
Arp inspection trusted ports
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip arp inspection trust
% endif
% endif 
#}}}

#{{{ URPF
% if uRPF is not None and (device.l3 == True and uRPF.mode is not None):
ConfigClassName:3.5 URPF
ConfigClassDescription:URPF related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

ConfigRuleName:3.5.1 Require chosen default urpf mode on every interface
ConfigRuleParentName:3.5 URPF
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:(.+Ethernet)|(Vlan.+)
ConfigRuleType:Required
ConfigRuleMatch:<code>(ip verify unicast source reachable-via ${'rx' if uRPF.mode.lower()=='strict' else 'any'})|^ switchport$|^ shutdown$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require chosen default urpf mode on every L3 interface
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 ip verify unicast source reachable-via ${'rx' if uRPF.mode.lower()=='strict' else 'any'}
% endif
#}}}

% if ipSourceGuard is not None:
ConfigClassName:3.6 IP source guard
ConfigClassDescription:IP source guard related rules 
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane
% if ipSourceGuard.vlanRange is not None:
ConfigRuleName:3.6.1 Require IP source guard to be enabled on given interfaces
ConfigRuleParentName:3.6 IP source guard
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:AccessPort
ConfigRuleInstance:${makeRegexOfContextInstanceList(makeListOfVlanRange(ipSourceGuard.vlanRange))}
ConfigRuleType:Required
ConfigRuleMatch:<code>ip verify source$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require IP source guard to be enabled on given interfaces 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 ip verify source

ConfigRuleName:3.6.2 Forbid IP source guard to be configured on other interfaces 
ConfigRuleParentName:3.6 IP source guard
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:AccessPort
ConfigRuleInstance:${makeNegRegexOfContextInstanceList(makeListOfVlanRange(ipSourceGuard.vlanRange))}
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip verify source$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid IP source guard to be configured on other interfaces 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip verify source
% else:
ConfigRuleName:3.6.1 Forbid IP source guard to be enabled on any interface
ConfigRuleParentName:3.6 IP source guard
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:AccessPort
ConfigRuleInstance:.*
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ ip verify source$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid IP source guard to be enabled on any interface 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 no ip verify source
% endif
% endif

ConfigRuleName:3.7 Limit number of MAC addresses on an interface
ConfigRuleParentName:3. Data plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>((no)* ip address.*)|(shutdown)|(no switchport)|(switchport mode trunk)|(switchport port-security maximum (\d+)$)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Limit number of MAC addresses on an interface 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
switchport port-security maximum 1

ConfigRuleName:3.8 Limit amount of broadcast traffic on an interface
ConfigRuleParentName:3. Data plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>((no)* ip address.*)|(shutdown)|(no switchport)|(switchport mode trunk)|(storm-control broadcast level \d+$)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Limit amount of broadcast traffic on an interface
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
switchport port-security maximum 1

ConfigRuleName:3.9 Forbid a non-shutdown interface in default configuration
ConfigRuleParentName:3. Data plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>(?!^interface \S+\n$).+</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid non-shutdown interface in default configuration
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
shutdown


#}}}

###################
#{{{ Control plane
###################
% if ntp is not None and ntp.hosts is not None:
ConfigClassName:2.1 NTP 
ConfigClassDescription:NTP related rules
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

<%
ntpServers=""
for i,ntpHost in ntp.hosts.items():
	ntpServers+="ntp server {0}\\\n".format(ntpHost)
ntpServers=ntpServers[:-2]

%>
ConfigRuleName:2.1.1 NTP servers 
ConfigRuleParentName:2.1 NTP 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${ntpServers}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require NTP servers
ConfigRuleSelected:Yes
ConfigRuleFix:<code>${ntpServers}</code>

% if ntp.acl is not None:
ConfigRuleName:2.1.2 NTP ACL 
ConfigRuleParentName:2.1 NTP 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(ntp.acl)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require an access-list to resctrict source of NTP queries
ConfigRuleSelected:Yes
ConfigRuleFix:<code>${printAcl(ntp.acl)}</code>

ConfigRuleName:2.1.3 NTP ACL applied 
ConfigRuleParentName:2.1 NTP 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ntp access-group peer ${getAclName(ntp.acl)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require an access-list to resctrict source of NTP queries to be applied
ConfigRuleSelected:Yes
ConfigRuleFix:<code>ntp access-group peer ${getAclName(ntp.acl)}</code>
% endif 
% endif

% if syslog is not None:
ConfigClassName:2.2 Syslog
ConfigClassDescription:Syslog events logging related rules 
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

% if syslog.hosts is not None:
<%
syslogHosts=""
for name,host in syslog.hosts.items():
	syslogHosts+="logging {0}\\\n".format(host)
syslogHosts=syslogHosts[:-2]
%>
ConfigRuleName:2.2.1 Syslog logging 
ConfigRuleParentName:2.2 Syslog
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${syslogHosts}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require a syslog server configured 
ConfigRuleSelected:Yes
ConfigRuleFix:<code>${syslogHosts}</code>

% if syslog.severity is not None:
ConfigRuleName:2.2.2 Syslog severity 
ConfigRuleParentName:2.2 Syslog
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>^logging facility ${syslog.severity}$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require a syslog facility configured 
ConfigRuleSelected:Yes
ConfigRuleFix:<code>logging facility ${syslog.severity}</code>

% endif 
% if syslog.facility is not None:
ConfigRuleName:2.2.3 Syslog severity 
ConfigRuleParentName:2.2 Syslog
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>^logging facility ${syslog.facility}$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require a syslog severity configured 
ConfigRuleSelected:Yes
ConfigRuleFix:<code>logging facility ${syslog.facility}</code>
% endif 
% endif
% endif

% if device.l3 and bgp:
ConfigClassName:2.3 BGP authentication
ConfigClassDescription:BGP authentication
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.3.1 Auth for every peer-policy
ConfigRuleParentName:2.3 BGP authentication
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:BGP_PeerTemplate
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>password.*</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require authentication defined within every peer-policy  
ConfigRuleSelected:Yes

ConfigRuleName:2.3.1 Auth for every BGP peer
ConfigRuleParentName:2.3 BGP authentication
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:BGP_Peer
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>(password.*|inherit peer-policy.*)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require peer-policy or explicit auth defined for every BGP peer  
ConfigRuleSelected:Yes
% endif 
#}}}

#{{{OSPF auth
% if device.l3 and ospf:
ConfigClassName:2.4 OSPF
ConfigClassDescription:OSPF related rules
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.4.1 OSPF default interface mode passive  
ConfigRuleParentName:2.4 OSPF  
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:OSPF_Router
ConfigRuleType:Required
ConfigRuleMatch:<code>passive-interface default$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require default mode for interfaces to be passive
ConfigRuleSelected:Yes

ConfigRuleName:2.4.2 Require message-digest auth for every OSPF area defined   
ConfigRuleParentName:2.4 OSPF  
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:OSPF_Router
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>^ area (\d+) (?!authentication message-digest)$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require message-digest auth for every OSPF area defined
ConfigRuleSelected:Yes
% endif 
#}}}

#{{{HSRP auth
% if device.l3 and hsrp:
ConfigClassName:2.5 HSRP 
ConfigClassDescription:HSRP
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.5.1 HSRP auth generic
ConfigRuleParentName:2.5 HSRP 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:HSRPGroup
ConfigRuleType:Required
ConfigRuleMatch:<code>standby group (\d+) authentication</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require an authentication to be configured in every HSRP group
ConfigRuleSelected:Yes

ConfigRuleName:2.5.2 HSRP MD5 auth generic
ConfigRuleParentName:2.5 HSRP 
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:HSRPGroup
ConfigRuleType:Required
ConfigRuleMatch:<code>standby group (\d+) authentication md5</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require an authentication (md5) to be configured in every HSRP group
ConfigRuleSelected:Yes
% endif 
#}}}

ConfigRuleName:2.6 Forbid CDP to run on endhost interfaces  
ConfigRuleParentName:2. Control plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleType:Required
ConfigRuleMatch:<code>((?!^interface \S+\n$).+)|(^ shutdown$)|((switchport mode trunk)|((?!^ switchport$)(.+\
)*^!$))|((switchport mode access\
)|(.+\
)*|^ no cdp run$)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid CDP to run on endhost interfaces
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE\
no cdp run

% if device.l2:
ConfigRuleName:2.7 Forbid DTP trunk negotiation  
ConfigRuleParentName:2. Control plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>(^ shutdown)|((no)* ip address.*)|(switchport mode (access|trunk))</code>
#ConfigRuleMatch:<code>(^ switchport\n(?!((.+\n)* switchport mode (access|trunk))))</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid DTP trunk negotiation  
ConfigRuleSelected:Yes
% endif 
# Spanning tree
% if device.l2:
ConfigClassName:2.8 STP 
ConfigClassDescription:STP related rules
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.8.1 Require STP portfast   
ConfigRuleParentName:2. Control plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>((no)* ip address.*)|(shutdown)|(switchport mode trunk)|(spanning-tree portfast$)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require STP portfast feature to be configured on access ports   
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
spanning-tree portfast

ConfigRuleName:2.8.2 Require STP BPDU guard   
ConfigRuleParentName:2. Control plane
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>((no)* ip address.*)|(shutdown)|(no switchport)|(switchport mode trunk)|(spanning-tree bpduguard enable$)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require STP BPDU guard feature to be configured on access ports   
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
spanning-tree bpduguard enable
% endif
#}}}

###################
#{{{Management plane
###################

#{{{Remote access

ConfigClassName:1.1 Access control rules
ConfigClassDescription:Access control
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

#{{{ VTY
% if vty:
ConfigClassName:1.1.1 Limit VTY remote access 
ConfigClassDescription:Limit remote access methods
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane 

% if vty.protocols is not None:
ConfigRuleName:1.1.1.1 VTY allowed input transport
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSLine
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>transport input ${getRegexOfList(vty.protocols.keys())}</code>
ConfigRuleImportance:10
ConfigRuleDescription:VTY allowed input transport
ConfigRuleSelected:Yes
ConfigRuleFix:line INSTANCE${"\\"}
transport input ${getRegexOfList(vty.protocols.keys())}
% else:
ConfigRuleName:1.1.1.1 VTY allowed input transport
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSLine
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>transport input none</code>
ConfigRuleImportance:10
ConfigRuleDescription:VTY allowed input transport
ConfigRuleSelected:Yes
ConfigRuleFix:line INSTANCE${"\\"}
transport input none
% endif 

% if device.ip4 and vty.acl is not None:
ConfigRuleName:1.1.1.2 Require VTY ACL for Ipv4 applied
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSLine
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>^ access-class ${getAclName(vty.acl)} in$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv4 applied
ConfigRuleSelected:Yes
ConfigRuleFix:line INSTANCE${"\\"}
access-class ${vty.acl} in

ConfigRuleName:1.1.1.3 Require VTY ACL for Ipv4 defined
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleInstance:
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(vty.acl)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv4 defined
ConfigRuleSelected:Yes
ConfigRuleFix:${printAcl(vty.acl)}
% endif 

% if device.ip6 and vty.acl6 is not None:
ConfigRuleName:1.1.1.4 Require VTY ACL for Ipv6 applied
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSLine
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>ipv6 access-class ${getAclName(vty.acl6)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv6 applied
ConfigRuleSelected:Yes
ConfigRuleFix:line INSTANCE${"\\"}
access-class ${vty.acl6} in

ConfigRuleName:1.1.1.5 Require VTY ACL for Ipv6 defined
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleInstance:
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(vty.acl6)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv6 defined
ConfigRuleSelected:Yes
ConfigRuleFix:${printAcl(vty.acl6)}
% endif 
#}}}

% endif 

ConfigRuleName:1.1.2 - Forbid Auxiliary Port
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleInstance:aux
ConfigRuleContext:IOSLine
ConfigRuleType:Required
ConfigRuleMatch:<code> no exec$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid Auxiliary Port
ConfigRuleSelected:yes
ConfigRuleOptional:no

ConfigRuleName:1.1.3 Forbid IP HTTP Server
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>no ip http server</code>
ConfigRuleImportance:10
ConfigRuleDescription:Disable HTTP server.
ConfigRuleSelected:yes

ConfigRuleName:1.1.4 Forbid IP HTTP Secure Server
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>no ip http secure-server</code>
ConfigRuleImportance:10
ConfigRuleDescription:Disable HTTPS server.
ConfigRuleSelected:yes

#{{{ SSH
ConfigClassName:1.2 SSH
ConfigClassDescription:Access control
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane 

ConfigRuleName:1.2.1 Configure the Host Name
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>hostname \S+</code>
ConfigRuleImportance:10
ConfigRuleDescription:Configure host name
ConfigRuleSelected:yes

ConfigRuleName:1.2.2 Configure the Domain Name
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>(ip domain-name \S+)|(ip domain name \S+)</code>
ConfigRuleImportance:7
ConfigRuleDescription:Configure the router�s domain name
ConfigRuleSelected:yes

#ConfigRuleName:1.2.3 - Generate the RSA Key Pair
#ConfigRuleParentName:1.2 SSH
#ConfigRuleVersion:version 1[0125]\.*
#ConfigRule#Context:IOSGlobal
#ConfigRuleType:Required
#ConfigRuleMatch:<code>crypto key \S+</code>
#ConfigRuleImportance:7
#ConfigRuleDescription:Generate an RSA ket pair.
#ConfigRuleSelected:yes

ConfigRuleName:1.2.4 - Require SSH Timeout value defined
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ip ssh timeout \d+</code>
ConfigRuleImportance:7
ConfigRuleDescription:Verify that an idle timeout has been configured for SSH sessions.
ConfigRuleSelected:yes

# login block-for should be better
#ConfigRuleName:1.2.5 - Limit the Number of SSH Authentication Tries
#ConfigRuleParentName:1.2 SSH
#ConfigRuleVersion:version 1[0125]\.*
#ConfigRule#Context:IOSGlobal
#ConfigRuleType:Required
#ConfigRuleMatch:<code>ip ssh authentication-retries \d+</code>
#ConfigRuleImportance:7
#ConfigRuleDescription:Verify the device is configured to limit the number of SSH authentication attempts.
#ConfigRuleSelected:yes

ConfigRuleName:1.2.6 - Require SSH version 2
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion:version 1[0125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ip ssh version 2</code>
ConfigRuleImportance:7
ConfigRuleDescription:Verify the device is configured to limit the number of SSH authentication attempts.
ConfigRuleSelected:yes
#}}}

#{{{ AAA, TACACS
% if aaa:
ConfigClassName:1.3 AAA
ConfigClassDescription:AAA
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

ConfigClassName:1.3.1 Tacacs
ConfigClassDescription:Tacacs
ConfigClassSelected:Yes
ConfigClassParentName:1.3 AAA

ConfigRuleName:1.3.1.1 AAA hosts and groups definition in a new format
ConfigRuleParentName:1.3.1 Tacacs
ConfigRuleVersion:version 1[5]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAAAServers(aaa)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:AAA (tacacs+,radius) hosts and groups definition in a new format
ConfigRuleSelected:Yes

ConfigRuleName:1.3.1.1 AAA hosts definition in a old format
ConfigRuleParentName:1.3.1 Tacacs
ConfigRuleVersion:version 1[012]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAAAServers_old(aaa)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:AAA (tacacs+,radius) hosts definition in a old format
ConfigRuleSelected:Yes


# possibly req line>login authentication console 
<%
aaa_methodsLists=[]
aaa_methodsListsTypes=[]

for line in aaa.methodsLists:
	methods=""
	for method in aaa.methodsLists[line]['methods']:
		methods+=method+' '
	methods=methods.strip()
	aaa_methodsLists.append(
		"aaa authentication {lineType} {name} {methods}\\\n".format(
			lineType=aaa.methodsLists[line]['type']['cisco'],
			name=line,
			methods=methods.replace('+','\+') #because of possible tacacs+
			)
		)
	aaa_methodsListsTypes.append(aaa.methodsLists[line]['type']['cisco'])
%>
% if aaa_methodsLists and len(aaa_methodsLists)>0:
ConfigClassName:1.3.1.1 AAA Methods lists
ConfigClassDescription:AAA methods lists 
ConfigClassSelected:Yes
ConfigRuleParentName:1.3.1 Tacacs


% for methodList in aaa_methodsLists:
ConfigRuleName:1.3.2.1.${loop.index+1} AAA method list n. ${loop.index+1}, ${aaa_methodsListsTypes[loop.index]}
ConfigRuleParentName:1.3.1.1 AAA Methods lists
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${aaa_methodsLists[loop.index]}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Required proper method lists to be configured
ConfigRuleSelected:Yes
% endfor

% else:
ConfigClassName:1.3.2.1 Method lists
ConfigClassDescription:AAA method lists 
ConfigClassSelected:No
ConfigRuleParentName:1.3.1 Tacacs
% endif 

% endif 

% if snmp:
ConfigClassName:1.4 SNMP
ConfigClassDescription:SNMP related rules 
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

% if snmp.communities is not None:
ConfigClassName:1.4.1 SNMP communities
ConfigClassDescription:SNMP related rules 
ConfigClassSelected:Yes
ConfigClassParentName:1.4 SNMP

ConfigClassName:1.4.2 ACLs for SNMP communities
ConfigClassDescription:SNMP related rules 
ConfigClassSelected:Yes
ConfigClassParentName:1.4 SNMP

% for index,com in snmp.communities.items():
ConfigRuleName:1.4.1.${loop.index+1} SNMP community 
ConfigRuleParentName:1.4.1 SNMP communities
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${printSnmpCommunity(index,snmp)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Required specific snmp communities to be defined
ConfigRuleSelected:Yes

% if 'acl_id' in com:
% if com['acl_id'] not in snmp.acls:
ConfigRuleName:1.4.2.${loop.index+1} ACL for SNMP community 
ConfigRuleParentName:1.4.1 ACLs for SNMP communities
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>!ERR: ACL ${com['acl_id']} not in snmp instance!</code>
ConfigRuleImportance:10
ConfigRuleDescription:Required acl for snmp community (1.4.2.${loop.index+1}) to be defined
ConfigRuleSelected:Yes
% else:
ConfigRuleName:1.4.2.${loop.index+1} ACL for SNMP community 
ConfigRuleParentName:1.4.2 ACLs for SNMP communities
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(snmp.acls[com['acl_id']])}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Required acl for snmp community (Rule number 1.4.2.${loop.index+1}) to be defined
ConfigRuleSelected:Yes
% endif
% endif 

% endfor

ConfigClassName:1.4.3 RO communities
ConfigClassDescription:SNMP related rules 
ConfigClassSelected:Yes
ConfigClassParentName:1.4 SNMP

<%
roComsRegex=''
for index,com in snmp.communities.items():
	if com['privilege']=='RO':
		roComsRegex+=com['community']+'|'
roComsRegex='('+roComsRegex[:-1]+')'
%>
ConfigRuleName:1.4.3.1 Forbid RO communities to defined also as RW 
ConfigRuleParentName:1.4.3 RO communities 
ConfigRuleVersion:version 1[125]\.*
ConfigRuleContext:IOSGlobal
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>snmp-server community ${roComsRegex} RW.*</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid RO communities to defined also as RW
ConfigRuleSelected:Yes
% endif
% endif
#}}}
#}}}
#}}}