#!/usr/bin/python
# Copyright (C) 2014 Amri Abdesslem
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#--------------------------------------------------------------------

__author__ = 'ask3m'

#--------------------------------------------------------------------

import os.path
import os
import gzip
import string

class pcapGzip:
    def __init__(self, pcapfile, reportpath="./report"):
        assert pcapfile
        if not os.path.exists(pcapfile):
            raise TypeError("Pcap file not found. Please check location.")
        self.reportpath = reportpath
        if not os.path.exists(self.reportpath):
            os.makedirs(self.reportpath)
        self.pcapfile = pcapfile

    def uncompressGzip(self, file):
        """Gunzip a gz file
        """
        try:
            r_file = gzip.GzipFile(file, 'r')
            write_file = string.rstrip(file, '.gz')
            w_file = open(write_file, 'w')
            w_file.write(r_file.read())
            w_file.close()
            r_file.close()
            os.unlink(file)
            print "Successfully uncompressed %s" % (file)
        except:
            print "***Error: Failed to uncompress %s" % (file)

    def tagFiles(self):
        """ Browses a given dir and tries to uncompress gz files
        """
        listDir = os.listdir("report")
        for f in listDir:
            fullpath = os.path.join(self.reportpath, f) # full path without gz extension
            if open(fullpath, 'r').read(2)=='\037\213': # magic number for application/x-gzip
                os.rename(fullpath, fullpath+".gz")     # first give gz extension to gz files
                self.uncompressGzip(fullpath+".gz")     # then uncompress gz files


