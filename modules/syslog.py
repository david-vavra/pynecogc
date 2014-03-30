__author__ = 'David Vavra'

from yapsy.IPlugin import IPlugin

class Syslog(IPlugin):
    def __init__(self):
        self.hosts=None
        self.facility=None
        self.severity=None

    def addServer(self,id,host):
        self.hosts={}
        if len(host)>0 and id is not None:
            self.hosts[id]=host

    def changeFacility(self,facility):
        self.facility=facility

    def changeSeverity(self,severity):
        self.severity=severity

    def parseContext(self,context,*args):
        for syslog in context.iter('syslog'):
            if 'severity' in syslog.attrib:
                self.changeSeverity(syslog.attrib['severity'])
            if 'facility' in syslog.attrib:
                self.changeSeverity(syslog.attrib['facility'])
            for host in syslog.iter('host'):
                self.addServer(
                    host.attrib['id'],
                    host.text
                )
