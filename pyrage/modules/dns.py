__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin


class DNS(IPlugin):
    def __init__(self):
        self.hosts = {}

    def addHost(self,id,host):
        self.hosts[id] = host

    def parseContext(self,context,*args):
        for dns in context.iter('dns_host'):
            for dnsServer in dns.iter('dns_host'):
                self.addHost(dnsServer.attrib['id'],dnsServer.text)


