# -*- coding: utf-8 -*-

"""
    Copyright (C) 2014  David Vavra  (vavra.david@email.cz)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""

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
        self.chosenLogLevel = self.loggingSeverity[logLevel] \
            if logLevel in \
               self.loggingSeverity else 0

    """
        Print given message on stderr output, if its severity is equal or less
        than chosen log level.
    """
    def log(self,msgSeverity,message):
        if msgSeverity not in self.loggingSeverity:
            msgSeverity = "warning"
        if self.loggingSeverity[msgSeverity] <= self.chosenLogLevel:
            sys.stderr.write(msgSeverity.capitalize()+':'+message + "\n")