<%!
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
        
def printAcl(acl):
    validAclTypes = ['standard','extended']
    separator = "!"
    output=""

    if acl is None:
        return "! Unable to print acl\n"

 
    # choose the acl name
    name=""
    isNumberedAcl=False
    if 'cisco' in acl.number:
    	name=acl.number['cisco']
    	isNumberedAcl=True
    elif len(acl.name)>0:
        name=acl.name
    else:
        return "! Unable to print acl\n"

    #get the acl type
    if 'cisco' in acl.type:
        if acl.type['cisco'] not in ['standard','extended']:
            return "! Unable to print acl: {0}\n".format(name)
        else:
            aclType = acl.type['cisco']
    else:
        if 'generic' not in acl.type:
            return "! Unable to print acl: {0}\n".format(name)
        elif acl.type['generic'] not in validAclTypes:
            return "! Unable to print acl: {0}\n".format(name)
        else:
            aclType = acl.type['generic']

    if len(aclType)==0:
        return "! Unable to print acl: {0}\n".format(str(acl.name))

    if aclType == 'standard':
        # standard
        lineSyntax = "%(action)s %(source_ip)s %(source_mask)s"
    else:
        # extended acl
        lineSyntax = "%(action)s %(protocol)s %(source_ip)s %(source_mask)s %(source_port)s %(destination_ip)s %(destination_mask)s %(destination_port)s %(state)s %(log)s"

    lineComment = "remark %(comment)s"
    
    # build the acl
    if not isNumberedAcl:
        output += 'ip access-list {aclType} {name}\n'.format(
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
                    return "! Unable to print acl: {0}\n".format(name)
                else:
                    lineArgs['seq'] = lineNum+1

            # the comment itself
            if isNumberedAcl:
                output += 'access-list {0} '.format(name) + lineComment % rule + '\n'
            else:
                output += lineNum + ' ' + lineComment % comment + '\n'


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
            output += 'access-list {0} '.format(name) + (lineSyntax % lineArgs).strip() + '\n'
        else:
            output += (lineSyntax % lineArgs).rstrip() + '\n'
    
    output=output.replace('0.0.0.0 255.255.255.255','any')
    output=re.sub(r'[ ]+',' ',output).strip()
    output=output.splitlines()
    output_mod=[]
    for line in output:
    	if line.find('remark') != -1:
    		output_mod.append(line)
    	else:
    		output_mod.append(line.replace('deny','deny  '))
        
    return '\n'.join(output_mod)

def getAclName(acl):
	if acl is None: 
		return ""
	if 'cisco' in acl.number:
		return acl.number['cisco']
	else: 
		return acl.name

""" AAA """
def printAAAServers(aaa):
	aaaServers=""
	""" print groups """
	if aaa.groups is not None:
		for groupName in aaa.groups:
			group = aaa.groups[groupName]
			aaaServers += "aaa group server {0} {1}\n".format(
				group['type'],
				groupName
				)
			
			for hostName in group['hosts']:
				aaaServers += " server name {0}\n".format(hostName)

	""" print hosts """
	if aaa.hosts is not None:
		for hostName in aaa.hosts:
			host = aaa.hosts[hostName]
			if 'ip' in host:
				aaaServers += "{0} server {1}\n".format(
					host['type'],
					hostName
				)
				aaaServers += " address ipv4 {0}\n".format(
					host['ip']
				)

	return aaaServers.strip()
	
def printAAAServers_old(aaa):
	output=""
	if aaa.hosts is not None:
		for host in aaa.hosts:
			output+="{1}-server host {0}.*\n".format(
				aaa.hosts[host]['ip'],
				aaa.hosts[host]['type'].lower())
	return output.strip()
	
def printAAAMethodsLists(aaa):
	aaa_methodsLists=""
	if aaa.methodsLists is not None:
		for line in aaa.methodsLists:
			methods=""
			for method in aaa.methodsLists[line]['methods']:
				methods+=method+' '
			methods=methods.strip()
			aaa_methodsLists+="aaa authentication {lineType} {name} {methods}\n".format(
					lineType=aaa.methodsLists[line]['type']['cisco'],
					name=line,
					methods=methods.replace('+','\+') # because of eventual tacacs+
					)
				
	return aaa_methodsLists.strip()
				
""" SNMP """ 
def printSnmpCommunities(snmp):
	if snmp.communities is None:
		return ""
	for id,com in snmp.communities.items():
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
		if com['aclId'] is not None:
			aclName = getAclName(snmp.acls[com['aclId']])
		else:
			aclName = ""
	return ("snmp-server community %s %s %s" % (
			community,
			priv,
			aclName
		)).strip()	

import re
from pyrage.acl import ACLv4
from pyrage.acl import ACLv6

def printSnmpViews(snmp):
	if snmp.views is None:
		return ""
	res=""
	for viewName in snmp.views:
		for op in snmp.views[viewName]:
			for tree in snmp.views[viewName][op]:
				res+="snmp-server view {name} {tree} {op}\n".format(
					name=viewName,
					tree=tree,
					op=op
				)
	return res

def printTraps(snmp):
	if snmp.traps is None:
		return ""
	printedTraps=[]
	res=""
	for tag,traps in snmp.traps.items():
		for trap in traps:
			if trap in printedTraps:
				continue
			printedTraps.append(trap)
			res+="snmp-server enable traps {0}\n".format(
				trap
			)
	return res

def printTrapServers(snmp):
	if snmp.trap_hosts is None or snmp.traps is None:
		return ""
	res=""
	for i,trapServer in snmp.trap_hosts.items():
		traps=[]
		for tag in trapServer['tags']:
			if tag in snmp.traps:
				traps+=snmp.traps[tag]
		traps=' '.join(set(traps))
		if len(traps)==0:
			continue

		res+="snmp-server host {host} traps version {version} {v3Params} {auth} {traps}\n".format(
			host=trapServer['host'],
			version=trapServer['version'],
			v3Params= trapServer['secLevel'] if trapServer['secLevel'] is not None else '',
			auth=trapServer['auth'],
			traps=traps
		)
	return re.sub(r'[ ]+',' ',res).strip()

def printSNMPUsers(snmp):
	if snmp.users is None:
		return ""
	res=""
	for id,user in snmp.users.items():
		if user['auth'] is None:
			auth=""
		else:
			if user['auth']['encrypted']:
				auth="ERR_ENCRYPTED_AUTH_STRING_NOT_SUPPORTED"
			else:
				auth="auth {type} {auth}".format(
					type=user['auth']['type'],
					auth=user['auth']['authString']
				)
		if user['priv'] is None:
			priv=""
		else:
			if user['priv']['encrypted']:
				priv="ERR_ENCRYPTED_PRIV_STRING_NOT_SUPPORTED"
			else:
				priv="priv {type} {auth}".format(
					type=user['priv']['type'],
					auth=user['priv']['authString']
				)
		if user['aclId'] is not None:
			if isinstance(snmp.acls[user['aclId']],ACLv4):
				acl=getAclName(snmp.acls[user['aclId']])
			elif isinstance(snmp.acls[user['aclId']],ACLv6):
				acl='ipv6 '+getAclName(snmp.acls[user['aclId']])
			else:
				acl="ERR_INVALID_ACL_INSTANCE"
		else:
			acl=""

		res+="snmp-server user {user} {group} v3 {auth} {priv} access {acl}\n".format(
			user=id,
			group=user['group'],
			auth=auth,
			priv=priv,
			acl=acl
		)
	return re.sub(r'[ ]+',' ',res).strip()

def printSNMPGroups(snmp):
	if snmp.groups is None:
		return ""
	res=""
	for name,group in snmp.groups.items():
		if group['views']['read'] is not None:
			readView="read {0}".format(group['views']['read'])
		else:
			readView=""
		if group['views']['write'] is not None:
			writeView="write {0}".format(group['views']['write'])
		else:
			writeView=""
		if group['aclId'] is not None:
			if isinstance(snmp.acls[group['aclId']],ACLv4):
				acl=getAclName(snmp.acls[group['aclId']])
			elif isinstance(snmp.acls[group['aclId']],ACLv6):
				acl='ipv6 '+getAclName(snmp.acls[group['aclId']])
			else:
				acl="ERR_INVALID_ACL_INSTANCE"
		else:
			acl=""

		res+="snmp-server group name {version} {secLevel} {readView} {writeView} {accessList}\n".format(
			version=group['version'],
			secLevel=group['secLevel'],
			readView=readView,
			writeView=writeView,
			accessList=acl
		)
	return re.sub(r'[ ]+',' ',res).strip()

def printSNMPAcls(snmp):
	if snmp is None or snmp.acls is None:
		return ""
	res=""
	for i,acl in snmp.acls.items():
		res+=printAcl(acl)
	return res	
%>
! --------------------------
! 			NTP  
% if ntp is not None and ntp.hosts is not None:
! ntp servers 
	% for i,host in ntp.hosts.items():
ntp server ${host}
	% endfor
! ntp acl 
	% if ntp.acl is not None:
		% if 'cisco' not in ntp.acl.number:
!	Unable to print ntp acl!
		% else:
ntp access-group peer ${ntp.acl.number['cisco']} 
${printAcl(ntp.acl)}
		% endif 
	% endif 
% endif
! --------------------------
! 			VTY
% if vty is not None:
	% if device.l2 == True:
interface Vlan1
shutdown
!
		% if vty.vlan is not None:
interface Vlan ${vty.vlan}
!
		% endif
		% if vty.gw is not None:
ip default-gateway ${vty.gw}
!
		% endif 
	% endif 	
vty 0 15 
	% if vty.acl is not None:
 access-class ${getAclName(vty.acl)} in	
	% endif
	% if vty.acl6 is not None:
 ipv6 access-class ${getAclName(vty.acl6)} in	
	% endif
	% if vty.protocols is not None:
 transport input ${" ".join(vty.protocols.keys())}
 end
conf t
		% if 'ssh' in vty.protocols:
crypto key generate rsa 2048
		% if 'version' in vty.protocols['ssh']:
ip ssh version ${vty.protocols['ssh']['version']}
		% endif
ip ssh timeout ${vty.protocols['ssh']['timeout']}
ip ssh authentication-retries ${vty.protocols['ssh']['retries']}
		% endif
	% else:
 transport input none
 	% endif
 exit
!
	% if vty.acl is not None:
${printAcl(vty.acl)}
	% endif
	% if vty.acl6 is not None:
${printAcl(vty.acl6)}	
	% endif
% endif
! --------------------------
! 			SYSLOG
% if syslog is not None:
	% if syslog.hosts is not None:
		% for i,host in syslog.hosts.items():
logging ${host}
		% endfor 
	% endif 
	% if syslog.facility is not None:
logging facility ${syslog.facility}
	% endif
	% if syslog.severity is not None:
logging trap ${syslog.severity}
	% endif
% endif
! --------------------------
! 			VTP 
% if vtp is not None:
	% if vtp.version is not None:
vtp version ${vtp.version}
	% endif 
	% if vtp.mode is not None:
vtp mode ${vtp.mode}
	% endif 	
	% if vtp.domain is not None:
vtp domain ${vtp.domain}
	% endif 	
% endif
! --------------------------
! 		DHCP SNOOPING
% if dhcpSnooping is not None:
	% if dhcpSnooping.trustedPorts is not None:
		% for port in dhcpSnooping.trustedPorts:
interface ${port}
 ip dhcp snooping trust
		% endfor 
end 
conf t
	% endif
	% if dhcpSnooping.vlanRange is not None:
ip dhcp snooping vlan ${dhcpSnooping.vlanRange}
	% endif 
% endif
! --------------------------
! 		ARP INSPECTION
% if arpInspection is not None:
	% if arpInspection.trustedPorts is not None:
		% for port in arpInspection.trustedPorts:
interface ${port}
 ip arp inspection trust
		% endfor 
end 
conf t
	% endif
	% if arpInspection.vlanRange is not None:
ip arp inspection vlan ${arpInspection.vlanRange}
	% endif 
% endif 
! --------------------------
!		IP SOURCE GUARD
% if ipSourceGuard is not None and ipSourceGuard.vlanRange is not None: 
! 
! VLAN RANGE ${ipSourceGuard.vlanRange}
!
% endif
! --------------------------
! 			DNS
% if dns is not None and dns.hosts is not None:
ip name-server ${' '.join(dns.hosts.values())}
% endif

% if device.l3:
! --------------------------
! 			uRPF
% if urpf is not None and urpf.mode is not None:
! SET URPF MODE ${urpf.mode} ON L3 INTERFACES !
! ip verify unicast source reachable-via ${'rx' if urpf.mode.lower()=='strict' else 'any'}
% endif 
% endif
! --------------------------
! 			AAA 
aaa new-model
% if aaa is not None:
! aaa servers
${printAAAServers(aaa)}
! aaa methods lists
${printAAAMethodsLists(aaa)}
! enable secret fallback 
enable secret 5 ! FIX 
! Console authentication 
line con 0
 password ! FIX  
 login authentication ! FIX
 stopbits 1
! vty fallback password 
line vty 0 15 
 password ! FIX 
% endif 
! --------------------------
! 			SNMP
% if snmp is not None:
${printSnmpCommunities(snmp)}
${printSnmpViews(snmp)}
${printTraps(snmp)}
${printTrapServers(snmp)}
${printSNMPGroups(snmp)}
${printSNMPUsers(snmp)}
${printSNMPAcls(snmp)}
% endif



		


