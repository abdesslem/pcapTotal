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
from scapy.all import *
sessionsList=[]
def getSessions(filename):
	pcap=rdpcap(filename)
	ses=pcap.sessions() # dict contain all the sessions 
	#('UDP 192.168.2.1:53 > 192.168.2.103:54756': <PacketList: TCP:0 UDP:1 ICMP:0 Other:0>')
	#len(s.values()[24])
	#return ses.keys()
        return getPacketList(ses,ses.keys())
	#p['TCP 192.168.2.103:49290 > 146.255.36.1:80'][1]
	#p['TCP 192.168.2.103:49290 > 146.255.36.1:80'][6]
	#p['TCP 192.168.2.103:49290 > 146.255.36.1:80'][2].load.split(' ')[2] 

def getPacketList(sessions,sessionKeys):
	#for key in sessionKeys:
        #if sessions[key][0].haslayer(IP):
        #     print sessions[key][0][1].src + ":" + str(sessions[key][0][1].sport) + "====>" + sessions[key][0][1].dst + ":" + str(sessions[key][0][1].dport)
        #sessionsList.append(sessions[key])       
	return sessions.keys()


