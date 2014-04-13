# Tacacs is hardcoded
# TODO: 
#		snmp
#		testing

<%!
def printComwareAcl(acl):
    def _getAclType(number):
        try:
            if int(number) in range(2000,2999):
                return 'standard'
            elif int(number) in range(3000,3999):
                return 'extended'
            else:
                return False
        except ValueError:
            return False

    if acl is None:
        return "# UNABLE TO PRINT ACL"

    """
    In comware based systems, acl are mainly disinguished based on their number.
    2000-2999 is equivalent of cisco standard ACLs
    3000-3999 is equivalent of cisco extended ACLs
    """
    output=''
    aclNum=''

    if 'comware' not in acl.number or not _getAclType(acl.number['comware']):
            return "# UNABLE TO PRINT ACL: '{0}'".format(acl.id)
    aclNum=acl.number['comware']

    """
    Decide whether given acl could be printed in comware syntax.
    """
    for id,rule in acl.rules.items():
        if _getAclType(aclNum)=='standard' and ('protocol' in rule or \
            'source_port' in rule or\
            'destination_port' in rule):
            """
            It is not possible for standard (2000-2999) acl to hold such attributes.
            """
            return "# UNABLE TO PRINT ACL: '{0}'".format(acl.id)

    if len(acl.name)>0:
        output+="acl number {num} name {name}\\\n".format(
            num=aclNum,
            name=acl.name
        )
    else:
        output+="acl number {num}\\\n".format(
            num=aclNum
        )
    for id,rule in acl.rules.items():
        lineNum=int(id)
        # build rule lines
        if 'optional' in rule and rule['optional']:
        	continue
        if 'comment' in rule:
            comment = rule['comment']
            # insert the comment line between the rules,
            if lineNum-1 in acl.rules:
                if lineNum+1 in acl.rules:
                    return "# UNABLE TO PRINT ACL: '{0}'".format(acl.id)
                else:
                    lineNum+=1

            # the comment itself
            else:
                output += 'rule ' + str(lineNum-1) + ' remark '+ comment + '\\\n'

        lineSyntax="rule %(seq)s %(action)s %(protocol)s %(source_ip)s %(source_mask)s %(source_port)s %(destination_ip)s %(destination_mask)s %(destination_port)s %(state)s %(log)s"
        lineArgs = defaultdict(str,rule)
        lineArgs['seq'] = id

        # build wildcard masks from bit-length repr.
        if lineArgs['source_mask']=='32':
        	lineArgs['source_mask']='0'
        if lineArgs['destination_mask']=='32':
        	lineArgs['destination_mask']='0'
        lineArgs['source_mask'] = "" if len(lineArgs['source_mask'])==0 else buildNetMask(lineArgs['source_mask'])
        # build a proper source/dest port def.syntax
        lineArgs['source_port']=('eq '+lineArgs['source_port']) if len(lineArgs['source_port']) else lineArgs['source_port']
        lineArgs['destination_port']=('eq '+lineArgs['destination_port']) if len(lineArgs['destination_port']) else lineArgs['destination_port']
        if _getAclType(aclNum) != 'standard':
            lineArgs['destination_mask'] = "" if len(lineArgs['source_mask'])==0 else buildNetMask(lineArgs['destination_mask'])
        lineArgs['log']='logging' if lineArgs['log']==True else ''
        output += (lineSyntax % lineArgs).rstrip() + '\\\n'

    output=output.replace('deny','deny  ')
    output=output.replace('0.0.0.0 255.255.255.255','any')
    """
    Normalize the format of resulting acl
    - strip any whitespace of width more than one
    """
    output=re.sub(r'[ ]+',' ',output)

    # strip newline at the end
    return output[:-2]

%>

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
ConfigPlatforms:HP Comware devices
ConfigFeedbackTo:vavra@ics.muni.cz
ConfigRulesAlias:hp-comware-benchmark.html

ConfigTrailingText:Please send a feedback about the benchmark to vavra@ics.muni.cz

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

ConfigRuleName:3.2 Forbid IP directed broadcast
ConfigRuleParentName:3. Data plane
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>ip forward-broadcast</code>
ConfigRuleFix:<code>undo ip forward-broadcast</code>
ConfigRuleDiscussion:HP Networking guide to hardening Comware-based devices


#{{{DHCP Snooping
% if dhcpSnooping:
ConfigClassName:3.3 DHCP snooping 
ConfigClassDescription:DHCP snooping related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

ConfigRuleName:3.3.1 Require DHCP snooping enabled
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>dhcp-snooping</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require DHCP snooping enabled
ConfigRuleSelected:Yes
ConfigRuleFix:<code>dhcp-snooping</code>


% if len(dhcpSnooping.trustedPorts)>0:
ConfigRuleName:3.3.2 Require DHCP trusted ports
ConfigRuleParentName:3.3 DHCP snooping
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareHwInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(dhcpSnooping.trustedPorts)}
ConfigRuleType:Required
ConfigRuleMatch:<code>dhcp-snooping trust</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require specific ports to be configured as DHCP snooping trusted ports
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
ip dhcp-snooping trust

% endif
% endif
#}}}

{{{# Arp inspection
% if arpInspection:
ConfigClassName:3.4 Arp inspection 
ConfigClassDescription:Arp inspection related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

ConfigRuleName:3.4.1 Require arp inspection enabled
ConfigRuleParentName:3.4 Arp inspection 
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareVlanInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(
							makeListOfVlanRange(arpInspection.vlanRange))}
ConfigRuleType:Required
ConfigRuleMatch:<code>arp detection enable</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require Arp inspection enabled
ConfigRuleSelected:Yes
ConfigRuleFix:<code>arp detection enable</code>

% if len(arpInspection.trustedPorts)>0:
ConfigRuleName:3.4.2 Require Arp trusted ports
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareHwInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(arpInspection.trustedPorts)}
ConfigRuleType:Required
ConfigRuleMatch:<code>arp detection trust</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require specific ports to be configured as Arp snooping trusted ports
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
arp detection trust

% else:
ConfigRuleName:3.4.3 Forbid Arp trusted ports
ConfigRuleParentName:3.4 Arp inspection
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareHwInterface
ConfigRuleInstance:${makeRegexOfContextInstanceList(arpInspection.trustedPorts)}
ConfigRuleType:Forbidden
ConfigRuleMatch:<code>arp detection trust</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require ARP inspection trusted ports
ConfigRuleSelected:Yes
% endif
% endif
#}}}

#{{{ URPF
% if uRPF is not None and device.l3 and uRPF.defaultMode is not None:
ConfigClassName:3.5 URPF
ConfigClassDescription:URPF related rules
ConfigClassSelected:Yes
ConfigClassParentName:3. Data plane

ConfigRuleName:3.5.3 Require urpf enabled in given mode
ConfigRuleParentName:3.5 URPF
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ip urpf ${uRPF.defaultMode.lower()}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require chosen default urpf mode on every interface
ConfigRuleSelected:Yes
ConfigRuleFix:<code>ip urpf ${uRPF.defaultMode.lower()}</code>
% endif
#}}}

ConfigRuleName:3.6 Limit number of MAC addresses on an interface
ConfigRuleParentName:3. Data plane
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareHwInterface
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>(port link-mode route)|(port link-type trunk)|(port-security max-mac-count (\d+))</code>
ConfigRuleImportance:10
ConfigRuleDescription:Limit number of MAC addresses on an interface 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
port-security max-mac-count 1

% if ipSourceGuard is not None and len(makeListOfVlanRange(ipSourceGuard.vlanRange))>0:
ConfigRuleName:3.7 Require IP source guard to be enabled on given interfaces
ConfigRuleParentName:3. Data plane
ConfigRuleVersion: version.*
ConfigRuleContext:AccessPort
ConfigRuleInstance:${makeRegexOfContextInstanceList(
						makeListOfVlanRange(ipSourceGuard.vlanRange))}
ConfigRuleType:Required
ConfigRuleMatch:<code>ip check source ip-address mac-address</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require IP source guard to be enabled on given interfaces 
ConfigRuleSelected:Yes
ConfigRuleFix:interface INSTANCE${"\\"}
 ip check source ip-address mac-address

% endif 
#}}}

###################
#{{{ Control plane
###################
% if ntp is not None and len(ntp.hosts)>0:
ConfigClassName:2.1 NTP 
ConfigClassDescription:NTP related rules
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

<%
ntpServersRegex=""
for i,ntpHost in ntp.hosts.items():
	ntpServersRegex+="ntp service unicast-server {0}\\\n".format(ntpHost)
ntpServersRegex=ntpServersRegex[:-2]
%>
ConfigRuleName:2.1.1 NTP servers 
ConfigRuleParentName:2.1 NTP 
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${ntpServersRegex}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require NTP server(s) to be configured
ConfigRuleSelected:Yes
ConfigRuleFix:${ntpServersRegex}

# srv-10g neodpovida na telnet host daytime 
% endif 

#{{{ SYSLOG TODO add severity and facility
% if syslog is not None and len(syslog.hosts)>0:
ConfigClassName:2.2 Syslog
ConfigClassDescription:Syslog events logging related rules 
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane
<%
syslogHosts=""
for name,host in syslog.hosts.items():
	syslogHosts+="info-center loghost {0}\\\n".format(host)
syslogHosts=syslogHosts[:-1]
%>
ConfigRuleName:2.2.1 Syslog logging 
ConfigRuleParentName:2.2 Syslog
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>${syslogHosts}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require a syslog server configured 
ConfigRuleSelected:Yes
% endif
#}}}

#{{{BGP auth
% if bgp:
ConfigClassName:2.3 BGP authentication
ConfigClassDescription:BGP authentication
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.3.1 Auth for every peer-policy
ConfigRuleParentName:2.3 BGP authentication
ConfigRuleVersion: version.*
ConfigRuleContext:BGP_Router
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>^ password.*</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require authentication defined within every peer-policy  
ConfigRuleSelected:Yes

ConfigRuleName:2.3.1 Auth for every BGP peer
ConfigRuleParentName:2.3 BGP authentication
ConfigRuleVersion: version.*
ConfigRuleContext:BGP_Group_OR_Peer
ConfigRuleInstance:.*
ConfigRuleType:Required
ConfigRuleMatch:<code>(peer (\S+) password.*|peer (\S+) group.*)</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require peer-group or explicit auth defined for every BGP peer  
ConfigRuleSelected:Yes
% endif 
#}}}

#{{{OSPF auth
% if ospf:
ConfigClassName:2.4 OSPF
ConfigClassDescription:OSPF related rules
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane

ConfigRuleName:2.4.1 OSPF default interface mode passive  
ConfigRuleParentName:2.4 OSPF  
ConfigRuleVersion: version.*
ConfigRuleContext:OSPF_Router
ConfigRuleType:Required
ConfigRuleMatch:<code>silent-interface.+</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require at least some interfaces to be defined as passive/silent. It is up to an administrator to decide which of them should or should not be configured as such.
ConfigRuleSelected:Yes
ConfigRuleDiscussion:HP Layer-3 IP Routing Configuration Guide
ConfigRuleFix:# CHECK OSPF PASSIVE INTERFACES!

ConfigRuleName:2.4.2 Require message-digest auth for every OSPF area defined   
ConfigRuleParentName:2.4 OSPF  
ConfigRuleVersion: version.*
ConfigRuleContext:OSPF_Router_Area
ConfigRuleType:Required
ConfigRuleMatch:<code>authentication-mode md5$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require message-digest auth for every defined OSPF area 
ConfigRuleSelected:Yes
ConfigRuleDiscussion:HP Layer-3 IP Routing Configuration Guide
ConfigRuleFix:ospf EDIT-BY-HAND${newline()} area EDIT-BY-HAND${newline()}  authentication-mode md5
% endif 

###################
#{{{Management plane
###################

#{{{Remote access

ConfigClassName:1.1 Access control rules
ConfigClassDescription:Access control
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

#{{{ VTY
% if vty and len(vty.protocols)>0:
ConfigClassName:1.1.1 Limit VTY remote access 
ConfigClassDescription:Limit remote access methods
ConfigClassSelected:Yes
ConfigClassParentName:2. Control plane 

ConfigRuleName:1.1.1.1 VTY allowed input transport
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareVTY
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>protocol inbound ${getRegexOfList(vty.protocols.keys())}</code>
ConfigRuleImportance:10
ConfigRuleDescription:VTY allowed input transport
ConfigRuleSelected:Yes

% if device.ip4:
<%
vty4_aclName="ERR_ACL_NOT_DEFINED"
if vty.acl_v4 is not None:
	if 'comware' in vty.acl_v4.name:
		vty4_aclName=vty.acl_v4.name['comware']
	elif 'generic' in vty.acl_v4.name:
		vty4_aclName=vty.acl_v4.name['generic']
%>
ConfigRuleName:1.1.1.2 Require VTY ACL for Ipv4 applied
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareVTY
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>^ acl ${vty4_aclName} inbound$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv4 applied
ConfigRuleSelected:Yes

ConfigRuleName:1.1.1.3 Require VTY ACL for Ipv4 defined
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleInstance:
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(vty.acl_v4)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv4 defined
ConfigRuleSelected:Yes
% endif 

% if device.ip6:
<%
vty6_aclName="ERR_ACL_NOT_DEFINED"
if vty.acl_v6 is not None:
	if 'comware' in vty.acl_v6.name:
		vty4_aclName=vty.acl_v4.name['comware']
	elif 'generic' in vty.acl_v6.name:
		vty4_aclName=vty.acl_v6.name['generic']
%>
ConfigRuleName:1.1.1.4 Require VTY ACL for Ipv6 applied
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareVTY
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>ipv6 access-class ${vty6_aclName}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv6 applied
ConfigRuleSelected:Yes

ConfigRuleName:1.1.1.5 Require VTY ACL for Ipv6 defined
ConfigRuleParentName:1.1.1 Limit VTY remote access
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>${printAcl(vty.acl_v6)}</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require VTY ACL for Ipv6 defined
ConfigRuleSelected:Yes
% endif 
#}}}
% endif

?????????
ConfigRuleName:1.1.2 - Forbid Auxiliary Port
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion: version.*
ConfigRuleInstance:aux
ConfigRuleContext:ComwareVTY
ConfigRuleType:Required
ConfigRuleMatch:<code> no exec$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Forbid Auxiliary Port
ConfigRuleSelected:yes
ConfigRuleOptional:no

ConfigRuleName:1.1.3 Forbid IP HTTP Server
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>undo ip http enable$</code>
ConfigRuleImportance:10
ConfigRuleDescription:Disable HTTP server.
ConfigRuleSelected:yes

ConfigRuleName:1.1.4 Forbid IP HTTP Secure Server
ConfigRuleParentName:1.1 Access control rules
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>undo ip https enable$</code>
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
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>sysname \S+</code>
ConfigRuleImportance:10
ConfigRuleDescription:Configure host name
ConfigRuleSelected:yes

# todo ? domain-name

ConfigRuleName:1.2.4 - Require VTY Timeout value defined
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareVTY
ConfigRuleInstance:vty.*
ConfigRuleType:Required
ConfigRuleMatch:<code>idle-timeout \d+ \d+</code>
ConfigRuleImportance:7
ConfigRuleDescription:Verify that an idle timeout has been configured for VTY sessions.
ConfigRuleSelected:yes

ConfigRuleName:1.2.5 - Limit the Number of SSH Authentication Tries
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ssh server authentication-retries \d+</code>
ConfigRuleImportance:7
ConfigRuleDescription:Verify the device is configured to limit the number of SSH authentication attempts.
ConfigRuleSelected:yes

ConfigRuleName:1.2.6 - Require SSH Authentication timeout to be defined
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ssh server authentication-timeout \d+</code>
ConfigRuleImportance:7
ConfigRuleDescription:Require SSH Authentication timeout to be defined.
ConfigRuleSelected:yes

ConfigRuleName:1.2.6 - Require SSH enabled
ConfigRuleParentName:1.2 SSH
ConfigRuleVersion: version.*
ConfigRuleContext:ComwareGlobal
ConfigRuleType:Required
ConfigRuleMatch:<code>ssh server enable</code>
ConfigRuleImportance:7
ConfigRuleDescription:Verify that ssh server runs.
ConfigRuleSelected:yes
#}}}

#{{{ AAA, TACACS
% if aaa:
ConfigClassName:1.3 AAA
ConfigClassDescription:AAA
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

# TODO test if tacacs in aaa 
ConfigClassName:1.3.1 Tacacs
ConfigClassDescription:Tacacs
ConfigClassSelected:Yes
ConfigClassParentName:1.3 AAA

ConfigRuleName:1.3.1.1 Require tacacs authentication server defined 
ConfigRuleParentName:1.3.1 Tacacs
ConfigRuleVersion: version.*
ConfigRuleContext:AAA_HWTACACS
ConfigRuleInstance:hwtac
ConfigRuleType:Required
ConfigRuleMatch:<code> primary authentication 147.251.7.17</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require tacacs authentication server defined
ConfigRuleSelected:Yes

ConfigRuleName:1.3.1.2 Require tacacs authentication methods list defined 
ConfigRuleParentName:1.3.1 Tacacs
ConfigRuleVersion: version.*	
ConfigRuleContext:AAA_Domain
ConfigRuleInstance:tacacs
ConfigRuleType:Required
ConfigRuleMatch:<code>  authentication default hwtacacs-scheme hwtac local</code>
ConfigRuleImportance:10
ConfigRuleDescription:Require tacacs authentication methods list defined 
ConfigRuleSelected:Yes
% endif 
#}}}

% if snmp:
ConfigClassName:1.4 SNMP
ConfigClassDescription:SNMP related rules 
ConfigClassSelected:Yes
ConfigClassParentName:1. Management plane

# TODO
% endif 
