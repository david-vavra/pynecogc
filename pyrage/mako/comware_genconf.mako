<%!
import re
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
        
def printSnmpTrapHost(trapHost):
    if trapHost is None:
        return "# UNABLE TO PRINT TRAP HOST"            
    try:
        if trapHost['version'] in ['1','2c']:
            return "snmp-agent target-host trap address udp-domain {host} udp-port 161 params securityname {principalName} v{version}\n".format(
                host=trapHost['host'],
                principalName=trapHost['auth'],
                version=trapHost['version']
            )
        elif trapHost['version'] in ['3']:
            """ Mapping of possible values to a Comware syntax """
            v3SecParamsMapping={
                None:'',
                'noauth':'',
                'auth':'authentication',
                'priv':'privacy'                    
            }
            return "snmp-agent target-host trap address udp-domain {host} udp-port 161 params securityname {principalName} v3 {secLevel}\n".format(
                host=trapHost['host'],
                principalName=trapHost['auth'],
                version=trapHost['version'],
                secLevel=v3SecParamsMapping[trapHost['secLevel'].lower()]
            )
        else:
            return "# UNABLE TO PRINT TRAP HOST - INVALID VERSION"
        
    except KeyError as e:
        return "# UNABLE TO PRINT TRAP HOST - {0}".format(str(e))
        
def printSnmpCommunity(snmpCom,acls):
    if snmpCom is None:
        return "# UNABLE TO PRINT SNMP COMMUNITY"
    try:
        aclName=''
        access=''
        if 'aclId' in snmpCom and snmpCom['aclId'] is not None:
            acl=acls[snmpCom['aclId']]
            aclName=acl.name if acl.name is not None else acl.number['comware']
        return "snmp-agent community {access} {com} {acl}".format(
            com=snmpCom['community'],
            access='write' if snmpCom['privilege'].lower()=='rw' else 'write',
            acl="acl "+aclName
        ).strip()
    except KeyError as e:
        return "# UNABLE TO PRINT SNMP COMMUNITY: {0}".format(str(e))

def printSnmpGroup(name,group,acls):
    if name is None or group is None:
        return "# UNABLE TO PRINT SNMP GROUP"
    privMapping={
        'noauth':'',
        'auth':'authentication',
        'priv':'priv'
    }
    rView = group['views']['read'] if group['views']['read'] is not None else ''
    wView = group['views']['write'] if group['views']['write'] is not None else ''
    try:
        aclName=''
        if 'aclId' in group and group['aclId'] is not None:
            acl=acls[group['aclId']]
            aclName=acl.name if acl.name is not None else acl.number['comware']
        output="snmp-agent group v3 {name} {priv} {rView} {wView} {acl}".format(
            name=name,
            priv=privMapping[group['secLevel'].lower()],
            rView='read '+rView,
            wView='write '+wView,
            acl="acl "+aclName
        ).strip()
        return re.sub(r'[ ]+',' ', output)
    except KeyError as e:
        return "# UNABLE TO PRINT SNMP GROUP: {0}".format(str(e))

def printSnmp3User(name,user,acls):
    if name is None or user is None:
        return "# UNABLE TO PRINT SNMP USER"
    auth=''
    priv=''
    aclName=''
    try:
        if 'aclId' in user and user['aclId'] is not None:
            acl=acls[user['aclId']]
            aclName=acl.name if acl.name is not None else acl.number['comware']
        if user['auth'] is not None:
            if user['auth']['encrypted']:
                return "# UNABLE TO PRINT SNMP USER: ENCRYPTED (HASHED) CREDENTIALS ARE NOT SUPPORTED"
            auth='authentication-mode {mode} {auth}'.format(
                mode=user['auth']['type'],
                auth=user['auth']['authString']
            )
        if user['priv'] is not None:
            if user['priv']['encrypted']:
                return "# UNABLE TO PRINT SNMP USER: ENCRYPTED (HASHED) CREDENTIALS ARE NOT SUPPORTED"
            priv='privacy-mode {mode} {auth}'.format(
                mode=user['priv']['type'],
                auth=user['priv']['privString']
            )                   
        output="snmp-agent usm-user v3 {name} {group} {auth} {priv} {acl}".format(
            name=name,
            group=user['group'],
            acl="acl "+aclName,
            auth=auth,
            priv=priv
        ).strip()
        return re.sub(r'[ ]+',' ', output)
                
    except KeyError as e:
        return "# UNABLE TO PRINT SNMP USER: {0}".format(str(e.message))
def getAclType(number):
    try:
        if int(number) in range(2000,2999):
            return 'standard'
        elif int(number) in range(3000,3999):
            return 'extended'
        else:
            return False
    except ValueError:
        return False
        
def printAcl(acl):
    if acl is None:
        return "# UNABLE TO PRINT ACL"

    """
    In comware based systems, acl are mainly disinguished based on their number.
    2000-2999 is equivalent of cisco standard ACLs
    3000-3999 is equivalent of cisco extended ACLs
    """
    output=''
    aclNum=''

    if 'comware' not in acl.number or not getAclType(acl.number['comware']):
        return "# UNABLE TO PRINT ACL: '{0}'".format(acl.id)

    aclNum=acl.number['comware']

    """ Decide whether given acl could be printed in comware syntax. """
    for id,rule in acl.rules.items():
        if getAclType(aclNum)=='standard' and (('protocol' in rule or 'source_port' in rule) or 'destination_port' in rule):
            """
            It is not possible for standard (2000-2999) acl to hold such attributes.
            """
            return "# UNABLE TO PRINT ACL: '{0}'".format(acl.id)

    if acl.name is not None:
        """ pokus """ 
        output+="acl number {num} name {name}\n".format(num=aclNum,name=acl.name)
    else:
        output+="acl number {num}\n".format(
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
                output += ' rule ' + str(lineNum-1) + ' remark '+ comment + '\n'

        lineSyntax=" rule %(seq)s %(action)s %(protocol)s %(source_ip)s %(source_mask)s %(source_port)s %(destination_ip)s %(destination_mask)s %(destination_port)s %(state)s %(log)s"
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
        if getAclType(aclNum) != 'standard':
            lineArgs['destination_mask'] = "" if len(lineArgs['source_mask'])==0 else buildNetMask(lineArgs['destination_mask'])
        lineArgs['log']='logging' if lineArgs['log']==True else ''
        output += (lineSyntax % lineArgs).rstrip() + '\n'

    output=output.replace('deny','deny  ')
    output=output.replace('0.0.0.0 255.255.255.255','any')
    """
    Normalize the format of resulting acl
    - strip any whitespace of width more than one
    """
    output=re.sub(r'[ ]+',' ',output)

    return output.rstrip()   
%> 

% if snmp is not Undefined:
snmp-agent sys-info version all
<% 
""" 
Comware does not support sending distinct groups of traps to multiple hosts.
Thus, the traps defined within all of the hosts are sent to every single one of them. 
""" 
%>
    % if snmp.traps is not None:
        % for tag,traps in snmp.traps.items():
            % for trap in traps:
snmp-agent trap enable ${trap}      
            % endfor
        % endfor 
    % endif 
    % if snmp.trap_hosts is not None:
        % for i,trapHost in snmp.trap_hosts.items():
${printSnmpTrapHost(trapHost)}      
        % endfor
    % endif
    % if snmp.views is not None:
        % for name,viewGroup in snmp.views.items():
            % if 'included' in viewGroup:
                % for subtree in viewGroup['included']:
snmp-agent mib-view included ${name} ${subtree}                 
                % endfor 
            % endif
            % if 'excluded' in viewGroup:
                % for subtree in viewGroup['excluded']:
snmp-agent mib-view excluded ${name} ${subtree}                 
                % endfor 
            % endif                     
        % endfor
    % endif

    % if snmp.communities is not None:
        % for i,community in snmp.communities.items():
${printSnmpCommunity(community,snmp.acls)}  
        % endfor
    % endif
    % if snmp.groups is not None:
        % for name,group in snmp.groups.items():
${printSnmpGroup(name,group,snmp.acls)}         
        % endfor
    % endif
    % if snmp.users is not None:
        % for name,user in snmp.users.items():
${printSnmp3User(name,user,snmp.acls)}
        % endfor
    % endif 
    % for id,acl in snmp.acls.items():
${printAcl(acl)}    
    % endfor
% endif
