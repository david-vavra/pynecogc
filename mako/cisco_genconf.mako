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
