#!/usr/bin/env python 
# ~http://www.pentestingskills.com~
# Author: Boumediene KADDOUR
# Name: PySniffy
# Network Sniffer
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import optparse

pdict={6: 'TCP',4: 'IPv4', 17:'UDP'}
apps_protos = {7 : 'echo', 20: 'ftp-data', 21: 'ftp',
		      22: 'ssh', 23: 'telnet', 25: 'smtp', 
		      53: 'domain', 67: 'bootps', 68: 'bootpc',
		      80: 'http', 110: 'pop3', 443: 'https' }
flags_codes = {1: 'F', 2:'S', 4 :'R', 8 : 'P', 16 :'A',17: 'FA', 18 : 'SA', 20 : "RA", 32 :'U',
		      41:'Xmas Attack', 0: 'Null Scan Attack', 63: "ALL SET"}
dhcp_msg_types = {1: 'DHCP Discover', 2: 'DHCP Offer', 3: 'DHCP Request',
		      4: 'DHCP Decline', 5: 'DHCP Acknowledgment', 6: 'DHCP NACK',
		      7: 'DHCP Release', 8: 'DHCPInform'}

def tcp_pkt_handler(pkt):
	if pkt.haslayer(TCP):
		try:
		 if pkt[TCP].sport < 1024 :
			sport = apps_protos[pkt[TCP].sport]
			dport = pkt[TCP].dport
		 elif pkt[TCP].dport < 1024:	
			dport = apps_protos[pkt[TCP].dport]
			sport = pkt[TCP].sport
	 	 else:
			sport =pkt[TCP].sport
			dport = pkt[TCP].dport
		 try:
		 	tcpopt = pkt[TCP].options[0][1]
	  	 	tstamp = pkt[TCP].options[2][1]
		 except:
			tcpopt = None
			tstamp = None
		 try:
			flagname = flags_codes[pkt[TCP].flags]
		 except:
			flagname = pkt[TCP].flags	 		
	  	
		 ops = (pkt[IP].src, pkt[IP].dst, sport, dport, pdict[pkt[IP].version],
		        pkt[IP].ttl, pdict[pkt[IP].proto], pkt[TCP].seq, pkt[TCP].ack, pkt[TCP].window,
		        flagname, tcpopt, tstamp,
	               )
	         temp = """
Info:
Src: %s , Dst: %s | Sport: %s , Dport: %s , \
IPvX: %s , TTL: %s , Proto: %s ,\
Seq: %s , Ack: %s , Window: %d , Flags: %s ,\
MSS: %s , Timestamp: %s 
		      """%ops
		 print temp
	   	except Exception as err:
		 print err

def udp_pkt_handler(pkt):
	if pkt.haslayer(UDP):
		try:	
		
			if pkt[UDP].sport < 1024 :
				sport = apps_protos[pkt[UDP].sport]
				dport = pkt[UDP].dport
		 	elif pkt[UDP].dport < 1024:	
				dport = apps_protos[pkt[UDP].dport]
				sport = pkt[UDP].sport
		 	else:
				sport =pkt[UDP].sport
				dport = pkt[UDP].dport
	
			global_ops  = (pkt[IP].src, pkt[IP].dst,sport, dport, pdict[pkt[IP].version],
			        pkt[IP].ttl, pdict[pkt[IP].proto])
			if pkt[UDP].payload.name == 'DNS':
				privateopts = (pkt[DNS].opcode, pkt[DNSQR].qname, pkt[DNSQR].qtype)
				glob = global_ops + privateopts
			else:
				pass#To be complete


			temp = """		
Info:
Src: %s , Dst: %s | Sport: %s , Dport: %s , \
IPvX: %s , TTL: %s , Proto: %s ,\
Opcode : %s , domain: %s , Record: %s\
				"""%glob

			print temp
		except Exception as err:
			print err
def arp_pkt_handler(pkt):
	if pkt.haslayer(ARP):
		if pkt[ARP].op == 1:
			req_temp = "Request : %s says: who-has %s tell %s"%(pkt.src, pkt[ARP].pdst, pkt[ARP].psrc)
			print req_temp
		else :
			output=(pkt.src, pkt[ARP].pdst, pkt[ARP].hwsrc, pkt[ARP].psrc)
			resp_temp = "Answer: %s tells: %s that %s is-at %s"%output
			print resp_temp

def icmp_pkt_handler(pkt):
	if pkt.haslayer(ICMP):
		if pkt[ICMP].type == 8:
			print "echo-request: %s Bytes from %s icmp_seq=%s ttl=%s to %s"%(pkt[IP].len, pkt[IP].src, str(pkt[ICMP].seq), pkt[IP].ttl, pkt[IP].dst)
		elif pkt[ICMP].type == 0: 
			print "echo-reply: %s Bytes from %s icmp-seq= %s ttl= %s to %s"%(pkt[IP].len, pkt[IP].src, pkt[ICMP].seq, pkt[IP].ttl,pkt[IP].dst)
		else :
			pass

def dhcp_pkt_handler(pkt):
	if pkt.haslayer(BOOTP):
		if pkt[DHCP].options and pkt[BOOTP].op == 1:
			opts = pkt[DHCP].options[0][0]+':'+dhcp_msg_types[pkt[DHCP].options[0][1]]+' '+pkt[DHCP].options[1][0]+':'+pkt[DHCP].options[1][1]	
			print "src %s TO dst %s | sport %s to dport %s | options : %s"%(pkt.src, pkt.dst, pkt[UDP].sport, pkt[UDP].dport, opts) 
		elif pkt[DHCP].options and pkt[BOOTP].op == 2:
		 	opts = pkt[DHCP].options[0][0]+':'+dhcp_msg_types[pkt[DHCP].options[0][1]]+' '+pkt[DHCP].options[1][0]+':'+pkt[DHCP]    .options[1][1]+' '+pkt[DHCP].options[2][0] + str(pkt[DHCP].options[2][1])+' '+ pkt[DHCP].options[3][0]+':'+str(pkt[DHCP].options[3][1]) + ' ' + pkt[DHCP].options[5][0] + " " + str(pkt[DHCP].options[5][1]) + ":" + pkt[DHCP].options[6][0] + ' '+ str(pkt[DHCP].options[6][1])
			
			print "src %s TO dst %s | sport %s to dport %s | options : %s"%(pkt.src, pkt.dst, pkt[UDP].sport, pkt[UDP].dport, opts) 
		else:
			pass		

def main():
	parser = optparse.OptionParser('usage %prog '+\
		'-i <Interface> -p <UDP|TCP|ARP|ICMP|DHCP>')
	parser.add_option('-i', dest='ifc', type='string', \
		help='specify Binding interface')
	parser.add_option('-p', dest='sproto', type='string', \
		help='specify the protocol to be sniffed')
	(options, args) = parser.parse_args()
	if (options.ifc == None) | (options.sproto == None):
		print parser.usage
		exit(0)
	else:
		sproto = options.sproto
		ifc = options.ifc
		udp = 'udp'
		tcp = 'tcp'
		arp = 'arp'
		icmp = 'icmp'
		dhcp = 'dhcp'
		if sproto.lower() == udp:
			sproto = udp_pkt_handler
		elif sproto.lower() == tcp:
			sproto = tcp_pkt_handler 
		elif sproto.lower() == arp:
			sproto = arp_pkt_handler
		elif sproto.lower() == icmp:
			sproto = icmp_pkt_handler
		elif sproto.lower() == dhcp:
			sproto = dhcp_pkt_handler
		else:
			print parser.usage
			exit(0)
	sniff(iface =ifc, prn=sproto)
if __name__ == '__main__':
	main()
