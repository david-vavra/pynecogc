__author__ = 'David Vavra'

import argparse
import sys
from mako.template import Template

"""
Config;rule;PassFail;Importance;Instance;Line
host;3.1 - Forbid IP source-route;FAIL;5;;2
host;3.2 Forbid IP directed broadcast;PASS;5;;
host;3.3.1 Require DHCP snooping enabled for specified vlans;FAIL;10;;2
host;3.3.2 Forbid any dhcp snooping trusted ports;FAIL;10;FastEthernet0/18;258
host;3.3.2 Forbid any dhcp snooping trusted ports;FAIL;10;GigabitEthernet0/1;425
host;3.4.1 Require arp inspection enabled;PASS;10;;
host;3.4.2 Forbid any Arp inspection trusted ports;FAIL;10;GigabitEthernet0/1;422
host;3.6.1 Forbid IP source guard to be enabled on any interface;PASS;10;;
host;3.7 Limit number of MAC addresses on an interface;FAIL;10;FastEthernet0/3;156

"""

FQDN_POS=0
RULE_POS=1
RESULT_POS=2
IMPORTANCE_POS=3
INSTANCE_POS=4
LINENUM_POS=5

def main():
    """
    Handle input args
    """
    argParser=argparse.ArgumentParser(description="Generates HTML report from ncat_out files.")
    argParser.add_argument('-t','--template',help="A path for html mako template")
    argParser.add_argument('device_audit_result',nargs='+')

    inputArgs=argParser.parse_args(sys.argv[1:])



    """
     try to open a template file
    """
    try:
        mkt=Template(open(inputArgs.template).read())#,lookup=lookup,strict_undefined=True)
    except IOError as e :
        sys.stderr.write('Error! Unable to open template file! {0}\n'.format(str(e)))

    """ try to open ncat outputs and build html pages from them """

    devices={}
    try:
        for devFile in inputArgs.device_audit_result:
            with open(devFile,'r') as f:
                lines=f.readlines()
                """ Example: #AuditDate=Mon Mar 31 02:05:28 2014 GMT """
                date=lines[-1].split('=')[1]

                """ lines with the actual results """
                lines=map(lambda f:f.strip().split(';'),lines[1:-1])
                for line in lines:
                    name=line[FQDN_POS]
                    if name not in devices:
                        devices[name]=DeviceAuditResults(name)
                    devices[name].addRuleResult(line)

                for name,dev in devices.items():
                    with open(name+'.html','w') as output:
                        print(str(dev.failed))
                        output.write(mkt.render(
                            date=date,
                            name=name,
                            deviceResults=dev
                        ))
    except IOError as e:
        sys.stderr.write('Error! {0}\n'.format(str(e)))

class DeviceAuditResults():
    def __init__(self,fqdn):
        self.fqdn=fqdn
        # importance : rule : instance , linenum
        self.failed={}
        self.passed={}

    def addRuleResult(self,res):
        print(res)
        """ we expect the list of len 6, which should be the result of line.split(';')"""
        assert len(res)==6
        assert res[RESULT_POS] in ['FAIL','PASS']


        if res[RESULT_POS]=='FAIL':
            container=self.failed
        else:
            container=self.passed
        if res[IMPORTANCE_POS] not in container:
            container[res[IMPORTANCE_POS]]={}
        container=container[res[IMPORTANCE_POS]]
        if res[RULE_POS] not in container:
            container[res[RULE_POS]]={}
        container=container[res[RULE_POS]]
        container[res[INSTANCE_POS]]=res[LINENUM_POS]


if __name__=="__main__":
    main()




