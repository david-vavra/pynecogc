__author__ = 'David Vavra'

import argparse
import sys
from mako.template import Template

"""
Config;rule;PassFail;Importance;Instance;Line
sw14.mgmt.ics.muni.cz;3.1 - Forbid IP source-route;FAIL;5;;2
sw14.mgmt.ics.muni.cz;3.2 Forbid IP directed broadcast;PASS;5;;
sw14.mgmt.ics.muni.cz;3.3.1 Require DHCP snooping enabled for specified vlans;FAIL;10;;2
sw14.mgmt.ics.muni.cz;3.3.2 Forbid any dhcp snooping trusted ports;FAIL;10;FastEthernet0/18;258
sw14.mgmt.ics.muni.cz;3.3.2 Forbid any dhcp snooping trusted ports;FAIL;10;GigabitEthernet0/1;425
sw14.mgmt.ics.muni.cz;3.4.1 Require arp inspection enabled;PASS;10;;
sw14.mgmt.ics.muni.cz;3.4.2 Forbid any Arp inspection trusted ports;FAIL;10;GigabitEthernet0/1;422
sw14.mgmt.ics.muni.cz;3.6.1 Forbid IP source guard to be enabled on any interface;PASS;10;;
sw14.mgmt.ics.muni.cz;3.7 Limit number of MAC addresses on an interface;FAIL;10;FastEthernet0/3;156

"""


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
    except IOError as e:
        sys.stderr.write('Error! Unable to open template file! {0}\n'.format(str(e)))

    """ try to open ncat outputs and build html pages from them """
    for dev in inputArgs.device_audit_result:
        try:
            with open(dev,'r') as f:
                lines=f.readlines()
                """ Example: #AuditDate=Mon Mar 31 02:05:28 2014 GMT """
                date=lines[-1].split('=')[1]
                name=dev.replace('ncat_out.txt','')
                """ lines with actual results """
                lines=map(lambda f:f.split(';'),lines[1:-1])
                print(lines)
                with open(name+'.html','w') as output:
                    output.write(mkt.render(
                        date=date,
                        name=name,
                        lines=lines
                    ))

        except IOError:
            sys.stderr.write('Error! {0}\n'.format(str(e)))


if __name__=="__main__":
    main()




