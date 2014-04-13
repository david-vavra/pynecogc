__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin

class VTP(IPlugin):

    def __init__(self):
        self.mode=None
        self.domain=None
        self.version=None


    def parseContext(self,context,*args):
        for vtp in context.iter('vtp'):
            if vtp.find('mode') is not None:
                self.mode=vtp.find('mode').text
            if vtp.find('version') is not None:
                self.version=vtp.find('version').text
            if vtp.find('domain') is not None:
                self.domain=vtp.find('domain').text

