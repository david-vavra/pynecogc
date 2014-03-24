<%inherit file="cisco_genconf.mako"/>

#{{{ printAcl

<%!
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
    # strip newline at the end
    output=output.replace('deny','deny  ')
    output=output.replace('0.0.0.0 255.255.255.255','any')
    
    return output[:-2]

def getAclName(acl):
	if acl is None: 
		return ""
	if 'cisco' in acl.number:
		return acl.number['cisco']
	else: 
		return acl.name
	
%>
#}}}


