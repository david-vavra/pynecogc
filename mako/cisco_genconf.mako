<%!
""" AAA """
def printAAAServers(aaa):
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

	return aaaServers.strip()
	
def printAAAServers_old(aaa):
	output=""
	for host in aaa.hosts:
		output+="{1}-server host {0}.*\\\n".format(
			aaa.hosts[host]['ip'],
			aaa.hosts[host]['type'].lower())
	return output.strip()
	
def printAAAMethodsLists():
	aaa_methodsLists=""
	for line in aaa.methodsLists:
		methods=""
		for method in aaa.methodsLists[line]['methods']:
			methods+=method+' '
		methods=methods.strip()
		aaa_methodsLists+="aaa authentication {lineType} {name} {methods}\\\n".format(
				lineType=aaa.methodsLists[line]['type']['cisco'],
				name=line,
				""" because of possible tacacs+ """
				methods=methods.replace('+','\+')
				)
			
	return aaa_methodsLists.strip()
				
""" SNMP """ 
def printSnmpCommunity(com):
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
	if 'acl' in com:
		aclName = getAclName(acl)
	else:
		acl_name = ""
	return ("snmp-server community %s %s %s" % (
		community,
		priv,
		aclName
	)).strip()	
%>
! --------------------------
! ntp 
% if ntp is not None and len(ntp.hosts)>0:
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
${printAcl(acl)}
		% endif 
	% endif 
% endif
! --------------------------
! vty
% if vty is not None:
	% if device.l2 == True:
! vty vlan
! 	vlan 1 should not be used 
interface Vlan1
shutdown
!
		% if vty.vlan != 1:
interface Vlan ${vty.vlan}
!
		% endif
! vty default gw	
		% if len(vty.gw)>0:
ip default-gateway ${vty.gw}
!
		% endif 
	% endif 	
! vty allowed protocols and access-lists assignment
vty 0 15 
	% if vty.acl_v4 is not None:
 access-class ${getAclName(vty.acl)} in	
	% endif
	% if vty.acl_v4 is not None:
 ipv6 access-class ${getAclName(vty.acl6)} in	
	% endif
	% if len(vty.protocols)>0:
 transport input ${" ".join(vty.protocols.keys()}
	% else:
 transport input none
 	% endif
 exit
!
! vty acls 
	% if vty.acl_v4 is not None:
${printAcl(vty.acl)}
	% endif
	% if vty.acl_v4 is not None:
${printAcl(vty.acl6)}	
	% endif
! ssh parameters 
crypto key generate rsa 2048
ip ssh version ${vty.protocols['ssh']['version']}
ip ssh timeout ${vty.protocols['ssh']['timeout']}
ip ssh authentication-retries ${vty.protocols['ssh']['retries']}
% endif
! --------------------------
! syslog
% if syslog is not None:
	% if len(syslog.hosts)>0:
		% for i,host in syslog.hosts.items():
logging ${host}
		% endfor 
	% endif 
	% if len(syslog.facility)>0:
logging facility ${syslog.facility}
	% endif
	% if len(syslog.severity)>0:
logging trap ${syslog.severity}
	% endif
% endif
! --------------------------
! vtp 
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
! dhcp snooping
% if dhcp_snooping is not None:
	% if dhcp_snooping.trustedPorts is not None:
		% for port in dhcp_snooping.trustedPorts:
interface ${port}
 ip dhcp snooping trust
		% endfor 
end 
conf t
	% endif
	% if dhcp_snooping.vlanRange is not None:
ip dhcp snooping vlan ${dhcp_snooping.vlanRange}
	% endif 
% endif
! --------------------------
! arp inspection
% if arp_inspection is not None:
	% if arp_inspection.trustedPorts is not None:
		% for port in arp_inspection.trustedPorts:
interface ${port}
 ip arp inspection trust
		% endfor 
end 
conf t
	% endif
	% if arp_inspection.vlanRange is not None:
ip arp inspection vlan ${arp_inspection.vlanRange}
	% endif 
% endif 
! --------------------------
! ip source guard 
% if ipSourceGuard is not None and ipSourceGuard.vlan_range is not None: 
! 
! VLAN RANGE ${ipSourceGuard.vlan_range}
!
% endif
! --------------------------
! DNS
% if dns is not None and dns.hosts is not None:
ip name-server ${' '.join(dns.hosts.values())}
% endif

% if device.l3:
! --------------------------
! uRPF
% if urpf is not None and urpf.mode is not None:
! SET URPF MODE ${urpf.mode} ON L3 INTERFACES !
! ip verify unicast source reachable-via ${'rx' if urpf.mode.lower()=='strict' else 'any'}
% endif 
% endif
! --------------------------
! AAA 
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
! --------------------------
! SNMP




		


