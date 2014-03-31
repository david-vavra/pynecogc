__author__ = 'David Vavra'


from pyrage import netparse

from mako.template import Template
from mako.lookup import TemplateLookup
import sys
import argparse

from netparse import Device
from netparse import NetworkParser
from logger import Logger

from utils import InvalidData


def main():

    """
    Handle input args
    """
    argParser=argparse.ArgumentParser(description="Generates network configuration from mako templates and parameters stored in xml")
    argParser.add_argument('-t','--template',help="A path for Mako template")
    argParser.add_argument('-n','--networkDef', help="Location of the network definition XML file")
    argParser.add_argument('device',nargs='+')
    #inputArgs=argParser.parse_args(sys.argv[1:])
    inputArgs=argParser.parse_args("-t mako/cisco_genconf.mako -n xml/devices-example.xml sw14.mgmt.ics.muni.cz".split(' '))

    logger = Logger('warning')

    """
     try to parse xml file
    """
    parser = NetworkParser(logger,inputArgs.networkDef)
    deviceInstances={}
    for dev in inputArgs.device:
        deviceInstances[dev]=Device(dev)
        try:
            parser.parseDevice(deviceInstances[dev])
        except InvalidData as e:
            logger.log('error',dev+e.msg)
            raise SystemExit(1)
    """
    Try to open open template
    """
    from mako import exceptions

    mkt=Template(open(inputArgs.template).read())
    for dev,instance in deviceInstances.items():
        f=open('{0}'.format(dev),'w')
        try:
            f.write(mkt.render(
                device=instance,
                **instance.instances))
        except:
            print (exceptions.text_error_template().render())
        f.close()
        sys.stdout.write("Generated configuration saved in file '{0}'.\n".format(dev))

if __name__=="__main__":
    main()