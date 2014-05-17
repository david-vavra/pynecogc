__author__ = 'David Vavra'

from pyrage.utils import ErrRequiredData
from pyrage.utils import ErrOptionalData

class ACL():
    """
    A container for ACLs parsed from a xml file.

    Arguments:
    network - a xml ElementTree instance which contains the acls
    """
    def __init__(self,network):
        self.contextToParse=network
        self.acl4={}
        self.acl6={}

    """
    Returns a parsed ACL instance.

    Arguments:
    aclId - an id to search for in ElementTree instance with which the class
            has been instanstiated
    IPver - version of ACL, 4 or 6
    """
    def parseAcl(self,aclId,IPver):
        if IPver not in [4,6]:
            raise ErrOptionalData("Invalid acl IP version specified: {0}".format(IPver))

        if IPver==4:
            if aclId in self.acl4:
                return self.acl4[aclId]
            for acl in self.contextToParse.iter('aclv4'):
                if 'id' in acl.attrib:
                    if acl.attrib['id']==aclId:
                        self.acl4[aclId]=ACLv4(aclId)
                        self.acl4[aclId].parseAcl(acl)
                        return self.acl4[aclId]
        else:
            if aclId in self.acl6:
                return self.acl6[aclId]
            for acl in self.contextToParse.iter('aclv6'):
                if 'id' in acl.attrib:
                    if acl.attrib['id']==aclId:
                        self.acl6[aclId]=ACLv6(aclId)
                        self.acl6[aclId].parseAcl(acl)
                        return self.acl6[aclId]
        raise ErrOptionalData(":ACL ({0}) not found in the XML file.".format(aclId))

class ACLv4():

    def __init__(self,aclId):

        self.id = aclId

        self.name='NOT DEFINED'
        self.number={}
        self.type={}
        self.rules={}

    def addName(self,name):
        if len(name)>0:
            self.name = name
    def addNumbers(self,**kwargs):
        for key,value in kwargs.items():
            self.number[key]=value

    def addTypes(self,**kwargs):
        for key,value in kwargs.items():
            self.type[key]=value

    def addRule(self,id,rule):
        assert rule and id
        self.rules[id]=rule

    def parseAcl(self,context):
        aclId = self.id
        acl=context
        """
            eventually add the acl's name
        """
        if acl.find('name') is not None:
            self.addName(acl.find('name').text)

        # add the acl number(s)
        aclNumbers={}
        for aclNumber in acl.iter('number'):
            aclNumbers[aclNumber.attrib['id']] = aclNumber.text
        self.addNumbers(**aclNumbers)

        aclTypes={}
        for aclType in acl.iter('type'):
            if 'id' not in aclType.attrib:
                aclTypes['generic'] = aclType.text
            else: aclTypes[aclType.attrib['id']] = aclType.text
        self.addTypes(**aclTypes)


        for rule in acl.iter('rule'):
            aclLine={}
            rule_id = int(rule.attrib['seq'])
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
                        aclLine['log'] = True
                if children.tag == 'protocol':
                    if 'state' in children.attrib:
                        aclLine['state'] = children.attrib['state']
            self.addRule(rule_id,aclLine)


class ACLv6():
    def __init__(self,aclId):

        self.id = aclId

        self.name='NOT DEFINED'
        self.rules={}

    def addName(self,name):
        if len(name)>0:
            self.name = name

    def addRule(self,id,rule):
        assert rule and id
        self.rules[id]=rule

    def parseAcl(self,context):
        aclId = self.id
        acl=context
        """
            eventually add the acl's name
        """
        if acl.find('name') is not None:
            self.addName(acl.find('name').text)

        for rule in acl.iter('rule'):
            aclLine={}
            rule_id = int(rule.attrib['seq'])
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
                        aclLine['log'] = True
                if children.tag == 'protocol':
                    if 'state' in children.attrib:
                        aclLine['state'] = children.attrib['state']
                self.addRule(rule_id,aclLine)
