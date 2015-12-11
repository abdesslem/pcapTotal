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
import requests
import json
from datetime import datetime
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
pkts= []
class parser:
        def reader(self,filename):
            #filename = 'uploads/file.pcap'
            #filename = os.path.join('/uploads', filename)
            packets = rdpcap(filename)
            for pkt in packets:
                res = self.parseSummary(pkt)
                pkts.append(res)
	    return pkts

	def parseSummary(self,rawPacket):
			l2 = rawPacket.summary().split("/")[0].strip()
			l3 = rawPacket.summary().split("/")[1].strip()
			srcIP, dstIP, L7protocol, size, ttl, srcMAC, dstMAC, L4protocol, srcPort, dstPort, payload ="---","---","---","---","---","---","---","---","---","---","---"
			payload = rawPacket[0].show
			if rawPacket.haslayer(Ether):
				srcMAC = rawPacket[0][0].src
				dstMAC = rawPacket[0][0].dst
			elif rawPacket.haslayer(Dot3):
				srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	if rawPacket.haslayer(STP):
			 		L7protocol = 'STP'
				 	payload = rawPacket[STP].show
			if rawPacket.haslayer(Dot1Q):
				l3 = rawPacket.summary().split("/")[2].strip()
				l4 = rawPacket.summary().split("/")[3].strip().split(" ")[0]
			if rawPacket.haslayer(ARP):
			 	srcMAC = rawPacket[0][0].src
			 	srcIP = rawPacket[0][0].src
			 	dstMAC = rawPacket[0][0].dst
			 	dstIP = rawPacket[0][0].dst
			 	L7protocol = 'ARP'
			 	payload = rawPacket[0].show
			#else if rawPacket.haslayer(DHCP):
			# 	#dostuff
			elif (rawPacket.haslayer(IP) or rawPacket.haslayer(IPv6)):
                                if rawPacket.haslayer(PPPoE):
                                    l3 = rawPacket.summary().split("/")[3].strip()
                                    l4 = rawPacket.summary().split("/")[4].strip().split(" ")[0]
                                else: 
				    l4 = rawPacket.summary().split("/")[2].strip().split(" ")[0]
				srcIP = rawPacket[0][l3].src
				dstIP = rawPacket[0][l3].dst
				if l3 == 'IP':
					size = rawPacket[0][l3].len
					ttl = rawPacket[0][l3].ttl
				elif l3 == 'IPv6':
					size = rawPacket[0][l3].plen
					ttl = rawPacket[0][l3].hlim
				L7protocol = rawPacket.lastlayer().summary().split(" ")[0].strip()
				if rawPacket.haslayer(ICMP):
					L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					payload = rawPacket[ICMP].summary().split("/")[0][5:]
				if rawPacket.haslayer(TCP) or rawPacket.haslayer(UDP) :
                                        if rawPacket.haslayer(PPPoE):
                                            L7protocol = rawPacket.summary().split("/")[4].strip().split(" ")[0]
                                            L4protocol = rawPacket.summary().split("/")[4].strip().split(" ")[0]
                                        else:
                                            L7protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
                                            L4protocol = rawPacket.summary().split("/")[2].strip().split(" ")[0]
					srcPort = rawPacket[0][l4].sport
					dstPort = rawPacket[0][l4].dport
			else:
				srcMAC = "<unknown>"
				dstMAC = "<unknown>"
				l4 = "<unknown>"
				srcIP = "<unknown>"
				dstIP = "<unknown>"
				payload = rawPacket[0].show
				
			packet = {"timestamp": str(datetime.now())[:-2],\
					"srcIP": srcIP,\
					"dstIP": dstIP,\
					"L7protocol": L7protocol,\
					"size": size,\
					"ttl": ttl,\
					"srcMAC": srcMAC,\
					"dstMAC": dstMAC,\
					"L4protocol": L4protocol,\
					"srcPort": srcPort,\
					"dstPort": dstPort,\
					"payload": rawPacket[0].show\
					}
			return packet
			#print str(packet["srcIP"])+":"+str(packet["srcPort"])

