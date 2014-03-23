# -*- coding: utf-8 -*-
"""
Created on Wed Dec 25 16:19:12 2013

@author: David Vavra
"""

from logger import Logger

from mako.template import Template
from mako.lookup import TemplateLookup
import sys
import argparse

from netparse import Device
from netparse import NetworkParser

from amber import InvalidData

import subprocess

def main():

    #
    # handle input args
    #
    argParser=argparse.ArgumentParser(description="Wrapper for router audit tool ncat.")
    argParser.add_argument('-t','--configType',help="Chooses the directory with configuration files for given audit among the others in ncat config dir")
    argParser.add_argument('-r','--rulesFile_template', help="Name of the mako template file in directory chosen with the -t option")
    argParser.add_argument('-n','--networkDef', help="Location of the network definition XML file")
    argParser.add_argument('device_cfg',nargs='+')
    inputArgs=argParser.parse_args(sys.argv[1:])

    logger = Logger('warning')

    #
    # try to parse xml file
    #
    parser = NetworkParser(logger,inputArgs.networkDef)
    deviceInstances={}
    for dev in inputArgs.device_cfg:
        deviceInstances[dev]=Device(dev)
        try:
            parser.parseDevice(deviceInstances[dev])
        except InvalidData as e:
            logger.log('error',dev+e.msg)
            raise SystemExit(1)

    #
    # generate ncat rules for every device
    #
    lookup=TemplateLookup(directories=['/home/sev/thesis/pyrage/docs'])
    mkt=Template(open(inputArgs.rulesFile_template).read(),lookup=lookup,strict_undefined=True)
    for dev,instance in deviceInstances.items():
        f=open('{0}.rules'.format(dev),'w')
        f.write(mkt.render(
            device=instance,
            bgp=True,
            ospf=True,
            hsrp=True,
            **instance.instances))
        f.close()

    #
    # launch ncat for every device
    #

    ncatOutputFilesString=[]
    allRules=""
    for dev,instance in deviceInstances.items():
        try:
            subprocess.check_call(['ncat',
                         '-t={0}'.format(inputArgs.configType),
                         '-r={0}'.format(dev+'.rules'),
                         dev])
        except subprocess.CalledProcessError as e:
            raise SystemExit(e.returncode)
        ncatOutputFilesString.append(dev+'.ncat_out.txt')
        allRules+=dev+'.rules,'

    try:
        subprocess.check_call(['ncat_report',
                         '-t={0}'.format(inputArgs.configType),
                         '-r={0}'.format(allRules[:-1]),
                         ]+(ncatOutputFilesString))

    except subprocess.CalledProcessError as e:
            raise SystemExit(e.returncode)





if __name__=="__main__":
    main()

      
