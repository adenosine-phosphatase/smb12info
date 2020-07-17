######################################################################################################################
# Exploit Title: SMB12 information gathering
# SMB12 means it's capable of inspecting both SMB1 and SMB2 versions 
# the utility will extract varios attributes from SMB protocol of the remote server such as
# OS version (only supported by SMB1 as per protocol definition)
# DNS computername, DNS domainname, NEtBIOS computername and NetBIOS domain name (SMB1 and SMB2)
# boot time and current time on the remote server (SMB1 and SMB2)
# Server's GUID (SMB1 and SMB2)
# Additional : NEtBIOS probe against UDP 137 (netbios session) to determine server roles such as
#		-domain master browser
# 		-domain controller
#		-server service
# Date: 11-July-2020
# Exploit Author: Ivica Stipovic
# Vendor Homepage: www.microsoft.com
# Software Link: intergrated as part of Windows OS
# Version: SMB1 and SMB2 
# Tested on: Windows 7, Windows 10, Windows 2012 R2, Windows 2016, Windows 2019 
# Domain setup: Some OS-es were setup as WORKGROUP members and some as DOMAIN 
# Objective: enhance system info returned by SMB protocol in comparison to :
# nmap smb-system-info.nse and metasploit smb_version and smb2 modules
# Known Limitation: not designed for SAMBA implementations (Linux etc) - no reliable detection/exception possible
###########################################################################################################

import socket
import sys
import time
from datetime import datetime, timedelta
from struct import *

TCP_PORT=445

netbios_check=(
		"\x91\xe2"		 					# Transaction ID
		"\x00\x00" 							# Flags
		"\x00\x01"							# Questions=1
		"\x00\x00"							# Answer RRs
		"\x00\x00"							# Authority RRs
		"\x00\x00"							# Additional RRs
		"\x20\x43\x4b\x41\x41\x41\x41\x41"	# Queries MSHOME/Type NB, Class IN
		"\x41\x41\x41\x41\x41\x41\x41\x41"
		"\x41\x41\x41\x41\x41\x41\x41\x41"
		"\x41\x41\x41\x41\x41\x41\x41\x41"
		"\x41\x00"
		"\x00\x21"							# NBSTAT (33)
		"\x00\x01")							# Class IN(1)

smb_helper_message=(
		"\x00" 								# NEtbios header - Message type 00
        "\x00\x00\x54" 						# Length
		"\xff\x53\x4d\x42" 					# SMB header-Server component
        "\x72" 								# SMB command - negotiate protocol
        "\x00" 								# NT Status - status_success
        "\x00" 								# NT Status
        "\x00\x00" 							# NT Status
        "\x18" 								# Flags: 0x18
        "\x01\x28" 							# Flags2
        "\x00\x00" 							# Process ID High
        "\x00\x00\x00\x00\x00\x00\x00\x00" 	# Signature
        "\x00\x00" 							# Reserved
        "\x00\x00" 							# Tree ID
        "\x2e\x6f" 							# Process ID
        "\x00\x00" 							# User ID
        "\x7f\xe6" 							# Multiplex ID
		"\x00" 								# Word Count
        "\x31\x00" 							# Byte count
        "\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00" # Requested Dialects
        "\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00" # PC NETWORK PROGRAM 1.0
        "\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20" # MICROSOFT NETWORKS 1.03
        "\x31\x2e\x30\x00" 				
        "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")

smb_enahanced_helper_message=(
		"\x00"								# NetBIOS header - message type 
		"\x00\x00\x45" 						# Length
		"\xff\x53\x4d\x42" 					# Server Component -SMB2
		"\x72" 								# Header Length
		"\x00\x00\x00\x00" 					# NT STATUS - status success
		"\x18" 								# Flags
		"\x53\xc8" 							# Flags2
		"\x00\x00" 							# Process ID High
		"\x00\x00\x00\x00\x00\x00\x00\x00" 	# Signature=00000
		"\x00\x00" 							# Reserved=0000
		"\xff\xff" 							# Tree ID
		"\xff\xfe" 							# Process ID
		"\x00\x00" 							# User ID
		"\x00\x00" 							# Multiplex ID
		"\x00" 								# Word Count
		"\x22\x00" 							# Byte count
		"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00" # Requested dialects - this is
		"\x02\x53\x4d\x42\x20\x32\x2e\x30\x30\x32\x00"     # the main difference to initial SMB1
		"\x02\x53\x4d\x42\x20\x32\x2e\x3f\x3f\x3f\x00")    # request

smb2_helper_message=(
		"\x00" 								# NetBIOS message type
		"\x00\x00\xae" 						# Length
		"\xfe\x53\x4d\x42" 					# SMB2 -Protocol ID
		"\x40\x00" 							# Header Length
		"\x00\x00" 							# Credit Charge
		"\x00\x00" 							# Channel sequence
		"\x00\x00" 							# Reserved
		"\x00\x00" 							# Negotiate Protocol
		"\x00\x00" 							# Credits requested
		"\x00\x00\x00\x00" 					# Flags
		"\x00\x00\x00\x00" 					# Chain offset
		"\x01\x00\x00\x00\x00\x00\x00\x00" 	# Message ID - unknown=1
		"\xff\xfe\x00\x00" 					# PRocess ID
		"\x00\x00\x00\x00" 					# Tree ID
		"\x00\x00\x00\x00\x00\x00\x00\x00" 	# Session ID
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # Signature 
		"\x24\x00" 							# Structure size
		"\x05\x00" 							# Dialect count
		"\x01\x00" 							# Security mode / signing enabled
		"\x00\x00" 							# Reserved
		"\x7f\x00\x00\x00" 					# Capabilities
		"\x86\xcc\xaa\x67\xca\xb6\xea\x11\x91\xb1\xfd\x77\x48\xa7\x6a\x3c" # Client GUID 
		"\x70\x00\x00\x00" 					# NegotiateContextOffset	
		"\x02\x00" 							# NEgotiateContextCount
		"\x00\x00" 							# Reserved
		"\x02\x02" 							# Dialect 1
		"\x10\x02" 							# Dialect 2
		"\x00\x03" 							# Dialect 3
		"\x02\x03" 							# Dialect 4
		"\x11\x03" 							# Dialect 5
		"\x00\x00" 							# unknonw
		"\x01\x00" 							# DataType SMB_PREAUTH
		"\x26\x00" 							# Datalength
		"\x00\x00\x00\x00" 					# Reserved
		"\x01\x00" 							# Hash Algorithm
		"\x20\x00" 							# salt length
		"\x01\x00" 							# Hash algorithm SHA-512
		"\xd3\x2f\xfe\xad\x6b\xc5\x32\xbb" 	# Salt (32 bytes)
		"\x44\x29\x7d\x56\x33\x69\xcd\xe7" 
		"\x42\x1c\x20\x53\x85\x16\x97\xc5" 
		"\x01\xec\x80\x12\x6a\x9b\xbe\x2d" 
		"\x00\x00" 							# unknown
		"\x02\x00" 							# SMB2_encryption_capabilities
		"\x06\x00" 							# Datalength
		"\x00\x00\x00\x00" 					# Reserved
		"\x02\x00" 							# Cipher count
		"\x02\x00" 							# Cipher ID
		"\x01\x00") 						# Cipher ID
		
smb_helper_message_security_blob=(
		"\x00" 								# NetBIOS message type
		"\x00\x00\x8f" 						# Length
		"\xff\x53\x4d\x42" 					# SMB1 Server Component
		"\x73" 								# Session Setup AndX (0x73)
		"\x00" 								# Error class=success
		"\x00" 								# Reserved
		"\x00\x00" 							# Error Code=no error
		"\x18" 								# Flags
		"\x01\x28" 							# Flags2
		"\x00\x00" 							# Process ID High
		"\x00\x00\x00\x00\x00\x00\x00\x00" 	# Signature
		"\x00\x00" 							# Reserved
		"\x00\x00" 							# Tree ID
		"\x2e\x6f" 							# Process ID
		"\x00\x00" 							# User ID	
		"\x7f\xe6" 							# Multiplex ID
		"\x0c" 								# Word Count
		"\xff" 								# AndX Command=no further commands
		"\x00" 								# Reserved
		"\x00\x00" 							# AndXOffset=0
		"\xdf\xff" 							# Max Buffer
		"\x02\x00" 							# Max Mpx Count
		"\x01\x00" 							# VC Number
		"\x00\x00\x00\x00" 					# Session Key
		"\x31\x00" 							# Security Blob Length
		"\x00\x00\x00\x00" 					# Reserved
		"\xd4\x00\x00\x80" 					# Capabilities
		"\x54\x00"							# Byte Count
		"\x4e\x54\x4c\x4d\x53\x53\x50\x00"  # NTLMSSP identifier	
		"\x01\x00\x00\x00" 					# NTLM Message Type = NTLMSSP_NEGOTIATE
		"\x05\x02\x88\xa2" 					# Negotiate flags
		"\x01\x00\x01\x00\x20\x00\x00\x00\x10\x00\x10\x00\x21\x00\x00\x00"		#Calling Wkst domain 
		"\x2e" 									
		"\x32\x54\x64\x44\x36\x30\x77\x62\x4e\50\x36\47\x39\x61\x66\x76" 		# Calling wkst name
		"\x57\x69\x6e\x64\x6f\x77\x73\x20\x32" 									# Native OS Win2000
		"\x30\x30\x30\x20\x32\x31\x39\x35\x00" 									# Native LAN Manager
	        "\x57\x69\x6e\x64\x6f\x77\x73\x20\x32" 
		"\x30\x30\x30\x20\x35\x2e\x30\x00")

smb2_helper_ntlmssp_message= (
		"\x00"								# Netbios Message Type 		
		"\x00\x00\xa2" 						# Length
		"\xfe\x53\x4d\x42" 					# Server Component, ex: SMB2
		"\x40\x00" 							# Header Length
		"\x01\x00" 							# Credit Charge
		"\x00\x00" 							# Channel sequence
		"\x00\x00" 							# Reserved
		"\x01\x00" 							# Session Setup
		"\x21\x00" 							# Credits requested
		"\x10\x00\x00\x00" 					# Flags
		"\x00\x00\x00\x00" 					# Chain Offset
		"\x02\x00\x00\x00\x00\x00\x00\x00" 	# Message ID
		"\xff\xfe\x00\x00" 		 			# Process ID
		"\x00\x00\x00\x00" 		 			# Tree ID
		"\x00\x00\x00\x00\x00\x00\x00\x00" 	# Session ID
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # Signature
		"\x19\x00" 							# Structure size
		"\x00" 								# Flags
		"\x02" 								# Security mode
		"\x01\x00\x00\x00" 					# Capabilities
		"\x00\x00\x00\x00" 					# Channel
		"\x58\x00" 							# Previous session ID
		"\x4a\x00" 							# Blob length
		"\x00\x00\x00\x00\x00\x00\x00\x00" 	# Previos Session ID
		"\x60\x48\x06\x06\x2b\x06\x01\x05" 	# GSS-API Generic Security Service 
		"\x05\x02\xa0\x3e\x30\x3c\xa0\x0e" 	# Simple Protected NEgotiation
		"\x30\x0c\x06\x0a\x2b\x06\x01\x04" 	# mechtypes + NTLM Secure Service Provider
		"\x01\x82\x37\x02\x02\x0a\xa2\x2a" 
		"\x04\x28\x4e\x54\x4c\x4d\x53\x53" 
		"\x50\x00\x01\x00\x00\x00\x97\x82" 
		"\x08\xe2\x00\x00\x00\x00\x00\x00" 
		"\x00\x00\x00\x00\x00\x00\x00\x00" 
		"\x00\x00\x0a\x00\xee\x42\x00\x00" 
		"\x00\x0f")
			

def print_smb12_system_info (smb_type,data2):
	
	netbios_header=4

	if smb_type==1:
		smb_header=32
	else:
		smb_header=64
	
        blob_offset=netbios_header+smb_header
        offset=0
    	index=0
    	size=len (data2)
		    		
	pattern=0
    	security_blob="4e544c4d535350"
    	control=""

    	for t in data2[blob_offset:size-blob_offset]:
		
		for x in data2[blob_offset+offset:blob_offset+offset+7]:
			control=control+"{:02x}".format(ord(x),"x")  
			

               	if security_blob==control:

			index=blob_offset+offset
			index=index+12
				
			targetnamelen=int(ord(data2[index:index+1][::-1]))

			index=index+28
			index=index+16

				
			targetname=data2[index:index+targetnamelen]			
			targetinfoitemlen=int(ord(data2[index+targetnamelen+2]))
			
			netbiosname=data2[index+targetnamelen+4:index+targetnamelen+4+targetinfoitemlen]
				
			netbioscomputernamelen=int(ord(data2[index+targetnamelen+4+targetinfoitemlen+2]))
			index=index+targetnamelen+4+targetinfoitemlen+2

			netbioscomputername=data2[index+2:index+2+netbioscomputernamelen]
			
			dnsdomainnamelen=int(ord(data2[index+2+netbioscomputernamelen+2]))
		 	index=index+2+netbioscomputernamelen+2

			dnsdomainname=data2[index+2:index+2+dnsdomainnamelen]
			
			dnscomputernamelen=int(ord(data2[index+2+dnsdomainnamelen+2]))
			index=index+2+dnsdomainnamelen+2

			dnscomputername=data2[index+2:index+2+dnscomputernamelen]
			
			print "[+] Target Name:", targetname
			print "[+] Netbios Domainname:",netbiosname
			print "[+] Netbios Computername:", netbioscomputername
			print "[+] DNS Domain Name:", dnsdomainname
			print "[+] DNS Computer Name:", dnscomputername
					
			index=index+2+dnscomputernamelen
			
# Check for DNS tree info item type - must be 5, anything else means not a domain member
			
			if int(ord(data2[index]))==5:
				dnstreelen=int(ord(data2[index+2]))
							
				print "[+] DNS Tree Name:", data2[index+2:index+2+dnstreelen+1]
				index=index+2+dnstreelen+2

# Skip over 16 bytes (timestamp=12 bytes + end-of-list=4 bytes
							
			index=index+16
			
			if size-index>0:
			
				print "[+] OS info:",data2[index-2:size]
	
		offset+=1
		control=""

def netbios_fingerprint():

	sockUDP=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	try:	
		sockUDP.sendto(netbios_check,(TCP_IP,137))
		sockUDP.settimeout(3)		
		dataUDP,addrUDP=sockUDP.recvfrom(1024)
		
		number_of_names=int(ord(dataUDP[56]))
		
		delta=0
		names_offset=57
		role=0
		
		for x in range(number_of_names):
			
			role=int(ord(dataUDP[names_offset+(x+1)*16-1+delta]))						
			if role==0:
				print ("[+] NetBIOS Role: Workstation/Redirector")
			elif role==32:
				print ("[+] NetBIOS Role: Server Service")
			elif role==28:
				print ("[+] NetBIOS Role: Domain Controller")
			elif role==27:
				print ("[+] NetBIOS Role: Domain Master Browser") 
			delta+=2
	
	except socket.timeout:
		print "[-] No response from NetBIOS"
		sockUDP.close()
	
def send_smb_request(message_type,sock_type):

	sock_type.sendall(message_type)
	resp,addr=sock_type.recvfrom(1024)
	return resp

def print_smb1_guid(smb1_guid_data):

	 guidA_id=""
	 guidB_id=""
	 guidC_id=""
	 guidD_id=""
	 guidE_id=""
	 for x in temp_data[73:77]:	
		guidA_id=guidA_id+"{:02x}".format(ord(x),"x")
      
    	 for x in temp_data[77:79]:
		guidB_id=guidB_id+"{:02x}".format(ord(x),"x")

    	 for x in temp_data[79:81]:
		guidC_id=guidC_id+"{:02x}".format(ord(x),"x")

    	 for x in temp_data[81:83]:
		guidD_id=guidD_id+"{:02x}".format(ord(x),"x")

    	 for x in temp_data[83:89]:
        	guidE_id=guidE_id+"{:02x}".format(ord(x),"x")
    
    	 print "[+] Server GUID:" ,guidA_id+'-'+guidB_id+'-'+guidC_id+'-'+guidD_id+'-'+guidE_id

def print_system_time(start_time,end_time,time_type):

# time_type=0 then boot time
# time_type=1 then current time

	dx=""
	for y in temp_data[start_time:end_time][::-1]:
		dx=dx+"{:02x}".format(ord(y),"x")

    	if dx!="0000000000000000":
    		us=int(dx,16) / 10.
		if time_type==0:
       			print "[+] Boot time:",datetime(1601,1,1) + timedelta(microseconds=us)    
		else:
			print "[+] Current time:", datetime(1601,1,1) + timedelta(microseconds=us)
    	else:
		if time_type==0:		
			print "[-] Boot time not specified"
		else:
			print "[+] Current time not specified"
    	dx=""


if len(sys.argv)!=2:
    print ("usage: python smbinject.py <ip address>")
    sys.exit()
else:
    TCP_IP=sys.argv[1]

#====================================
# Negotiate Protocol Request sequence
#=====================================

print ("[+] Trying NetBIOS fingerprint...")

netbios_fingerprint()

sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect((TCP_IP,TCP_PORT))

try:
    print ("[+] Starting SMB1 check")
    temp_data=send_smb_request(smb_helper_message,sock)	
    smb_dialect=temp_data[72:74]
  
    current_time_start=60
    current_time_stop=68

    print_system_time(current_time_start,current_time_stop,1)
    print_smb1_guid(temp_data)

    print ("[+] SMB1 dialect detected")
    time.sleep(1) 

    data=send_smb_request(smb_helper_message_security_blob,sock)
    print ("[+] SMB response")
    
    smb=1
    print_smb12_system_info (smb,data)

except socket.error,ex:
    print ("[-] Server reset SMB1 negotiation. Trying SMB2 ...")
    sock2=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock2.connect((TCP_IP,TCP_PORT))
  
    temp_data=send_smb_request(smb_enahanced_helper_message,sock2)
 
    guid1_id=""
    guid2_id=""
    guid3_id=""
    guid4_id=""
    guid5_id=""

    for x in temp_data[76:80][::-1]:	
	guid1_id=guid1_id+"{:02x}".format(ord(x),"x")
      
    for x in temp_data[80:82][::-1]:
	guid2_id=guid2_id+"{:02x}".format(ord(x),"x")

    for x in temp_data[82:84][::-1]:
	guid3_id=guid3_id+"{:02x}".format(ord(x),"x")

    for x in temp_data[84:86]:
	guid4_id=guid4_id+"{:02x}".format(ord(x),"x")

    for x in temp_data[86:92]:
        guid5_id=guid5_id+"{:02x}".format(ord(x),"x")
    
    print "[+] Server GUID:" ,guid1_id+'-'+guid2_id+'-'+guid3_id+'-'+guid4_id+'-'+guid5_id
    
    dt=""

    current_time_start=108
    current_time_stop=116
    boot_time_start=116
    boot_time_stop=124

    print_system_time(current_time_start,current_time_stop,1)
    print_system_time(boot_time_start,boot_time_stop,0)

    time.sleep(2) 	
 
    send_smb_request(smb2_helper_message,sock2)
    time.sleep(1)
  
    data2=send_smb_request(smb2_helper_ntlmssp_message,sock2)   

    smb=2
    print_smb12_system_info (smb,data2)

    sock2.close()

sock.close()

