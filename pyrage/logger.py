__author__ = 'sev'

import sys

class Logger():
    def __init__(self,logLevel):
        self.loggingSeverity = {
                            "critical":0,
                            "error":1,
                            "warning":2,
                            #"info":3,
                            #"debug":4
        }
        self.chosenLogLevel = self.loggingSeverity[logLevel]

    """
        Print given message on stderr output, if its severity is equal or less
        than chosen log level.
    """
    def log(self,msgSeverity,message):
        if msgSeverity not in self.loggingSeverity:
            msgSeverity = "warning"
        if self.loggingSeverity[msgSeverity] <= self.chosenLogLevel:
            sys.stderr.write(msgSeverity.capitalize()+':'+message + "\n")