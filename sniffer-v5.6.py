#!/usr/bin/env python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import time
import logging
import sys
from scapy.all import *
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl
import gpsd

ap_list = []
ap_array_list = []
packet_count = 0
packet_sub58 = 0
packet_sub4 = 0
packet_datatype = 0
rejects = 0
################################################################
# Cheat codes for characters                                 ###
################################################################
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan
CLR = '\033c'   # clear screen
CR = '\n'	# carriage return
D  = ';'      	# delimiter

#File objects
#logfileVictim=open('victim-beacons','a')
#logfileAccess=open('access-beacons','a')

#database message format
database_message_pkt =("{};{};{};{}")

################################################################
# START ARGS FROM COMMANDLINE   -- STOLEN CODE / KINDA       ###
################################################################
def parse_args():
    #Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--interface", help="Choose monitor mode interface. By default script will find the most powerful interface and starts monitor mode on it. Example: -i mon5")
    parser.add_argument("-c", "--channel", help="Listen on and deauth only clients on the specified channel. Example: -c 6")##
    parser.add_argument("-m", "--maximum", help="Choose the maximum number of clients to deauth. List of clients will be emptied and repopulated after hitting the limit. Example: -m 5")
    parser.add_argument("-n", "--noupdate", help="Do not clear the deauth list when the maximum (-m) number of client/AP combos is reached. Must be used in conjunction with -m. Example: -m 10 -n", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001")
    parser.add_argument("-p", "--packets", help="Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2")
    parser.add_argument("-d", "--directedonly", help="Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs", action='store_true')
    parser.add_argument("-a", "--accesspoint", help="Enter the MAC address of a specific access point to target")
    parser.add_argument("-w","--world", help="N. American standard is 11 channels but the rest of the world it's 13 so this options enables the scanning of 13 channels")
    parser.add_argument("-x", "--targetdeck", help="Standard display will disabled and only the target MACs will be displayed as they are found. Path to target deck is expected")

    return parser.parse_args()
################################################################
# END ARGS FROM COMMANDLINE      -- STOLEN CODE / KINDA      ###
################################################################

################################################################
# INTERFACE SETUP                -- STOLEN CODE / KINDA      ###
################################################################
def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        #return monitors[0]
	return monitors
    else:
	    #We will not be allowing the code to select its own card - This can FUCK UP COMMUNICATIONS
        #Start monitor mode on a wireless interface
    	print CLR
        print '['+G+'*'+W+'] Enter interface name to start monitoring on'
	ouput = os.popen("ifconfig").readlines()
	print '['+G+'*'+W+'] Interface names are case sensitive'
        interface = raw_input()
        monmode = start_mon_mode(interface)
    return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('['+R+'-'+W+'] Could not execute "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces
	
def start_mon_mode(interface):
    print '['+G+'+'+W+'] Starting monitor mode off '+G+interface+W
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')

def remove_mon_iface(mon_iface_list):
    for mon_iface in mon_iface_list:
	os.system('ifconfig %s down' % mon_iface)
        os.system('iwconfig %s mode managed' % mon_iface)
        os.system('ifconfig %s up' % mon_iface)

def mon_mac(mon_iface_list):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    for mon_iface in mon_iface_list:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon[:15]))
        mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
        print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
	append.mon_mac_list(mac)
    return mon_mac_list
################################################################
# END INTERFACE SETUP                -- STOLEN CODE / KINDA  ###
################################################################	

################################################################
# Set channel hop behavior                                     #
################################################################





################################################################
# START OUTPUT FUNCTION                                      ###
################################################################
"""AirDump Output clone -- stolen from github and basically completely rewritten. This will be shot 
off in its own thread so we don't slow down the packet capture"""
def output():
 while 1:
    print CLR
   
    if len(APs) > 0:
        print '\n     Acess Points      ch   RSSI     ESSID'
        with lock: 
            for ap in APs:
                print '['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[3].ljust(2)+W+' - '+T+ap[4].ljust(2)+W+' - '+O+ap[2]+W
    print ''
    
    if len(clients_APs) > 0:
        print '     Data Traffic Pairs Type 1/2            ch       Source     ESSID'
    # Print the clients list
        with lock:
            for ca in clients_APs:
                try:
                     if len(ca) > 4:
                         print '['+T+'*'+W+'] '+O+ca[0]+W+' --> ' +O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W+' - '+T+ca[4]
                     else:
                         print '['+T+'*'+W+'] '+O+ca[0]+W+' --> ' +O+ca[1]+W+' - '+ca[2].ljust(2)+' - '+T+ca[3]+W
                except:
                    continue
                        
    if len(evil_twins_list) > 0: 
        print '\n     Victim MAC   Packet Count   Potential Twin SSID'
        with lock: 
            for et in evil_twins_list:
                try:
                    if len(et) > 0: 
                        print '['+T+'**'+W+'] '+O+et[0]+W+' - '+T+et[2]+W+' - '+T+et[1]
                except:
                    continue
			 
    if packet_count > 0:
            print G+'\nPackets:    |     ' + str(packet_count) +B+ '\nType 5/8:   |     ' + str(packet_sub58) +B+ '\nType 4:     |     ' + str(packet_sub4) +B+ '\nData:       |     ' + str(packet_datatype) +R+'\nFiltered:   |     ' + str(rejects)

    try:
        print '\n'+W+ str(gpsd.get_current())
    except:
        continue

    if len(current_channel_list) > 0:
        for cur in current_channel_list:
            print '['+G+'+'+W+'] '+cur[0]+' channel: '+G+cur[1]+W+' - '+cur[2]

    time.sleep(1.5)

def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    # The orginal version was broken, this is a functioning version
    ignore = ['ff:ff:ff', '00:00:00', '33:33:00', '33:33:ff', '01:80:c2', '01:00:5e']
    if (str(addr1)[:8]) in ignore or (str(addr2)[:8]) in ignore:
        return True
    else: 
        return False

def target_verification(address, target_list):
    if (str(address)) in target_list:
        return True
    else:
        return False

def file_target_deck_selection(args,side_load):
    if args.hunter and side_load =='':
        with lock:
            target_full_path = args.hunter
    else:
        target_full_path = side_load
    while(False):
        try: 
            target_file = open(target_full_path)
            return True
        except:
            print("Bad path to target deck, please enter path")
            target_full_path=raw_input()
            return False
    return target_file

def read_target_deck_selection(target_file):
    target_list = []
    target_list = target_file.read().split("\n")
    target_file.close()
    return target_list 

##############################################################
# END OUTPUT FUNCTION                                      ###
##############################################################








##############################################################
# Start PACKETMONTSTER function                              #
##############################################################
def PacketMonster(mon_iface,channelDirection,args):
# This defines local functions and allows for options to be 
# passed via PRN. It is not being used currently but better 
# to start with it. We are nesting a functions to allow for 
# later expansion. Also this allows for thread spawning
 mon_iface_local=
 
    def get_channels(mon_iface):
         channels = []
         try:
             proc = Popen(['iwlist',mon_iface,'freq'], stdout=PIPE, stderr=DN)
         except OSError:
             sys.exit('['+R+'-'+W+'] Could not execute "iwlist"')
         for line in proc.communicate()[0].split('\n'):
              if len(line) == 0:
                   continue
              if line[0] == ' ':
                   fields =line.strip().split()
                   if (str(fields[0])) == "Channel":
                        channels.append(str(fields[1]))
         return channels

    def channel_hop(mon_iface,channelDirection,args):
    '''
    First time through, scan each channel for 2 seconds.
    Then skip through all channels quickly.
    '''
         global first_pass, current_channel_list
         if not args.world:
              chans_local = get_channels(mon_iface)
         if channelDirection == 'down':
              channelNumPos = len(chans_local)
         elif channelDirection == 'up':
              channelNumPos = -1

         err = None
         while 1:
              if args.channel:
                   with lock:
                        monchannel_local = args.channel
              else:
                   if channelDirection =='up':
                        channelNumPos +=1
                        if channelNumPos > len(chans_local)-1:
                             channelNumPos -=1
                        channelDirection = 'down'
                        with lock:
                             first_pass = 0
                   elif channelDirection == 'down':
                        channelNumPos -=1
                        if channelNumPos == -1:
                             channelNumPos +=1
                             channelDirection = 'up'
              monchannel_local = str(chans_local[channelNumPos])
              try:
                   proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel_local], stdout=DN, stderr=PIPE)
              except OSError:
                   print '['+R+'-'+W+'] Could not execute "iw"'
                   os.kill(os.getpid(),SIGINT)
                   sys.exit(1)
              for line in proc.communicate()[1].split('\n'):
                   if len(line) > 2: # iw dev shouldnt display output unless there's an error
                        err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W
         if args.channel:
              time.sleep(.05)
         else:
              with lock:
                   current_channel(current_channel_list,mon_iface,monchannel_local,channelDirection)
                   if first_pass == 1:
                        time.sleep(1)
                   continue
              time.sleep(.75)   
       #code here for Mass-Deauth but its neutered

    def PacketHandler(pkt):
         global rejects
         if pkt.type not in [0,1,2] or (noise_filter(pkt.addr1,pkt.addr2) == True and pkt.subtype != 4):
              rejects=rejects+1
              return
         if pkt.type == 0 and pkt.subtype not in [4,5,8]:
              rejects-rejects+1
              return
         rssi_local = -100
         time_stamp_local = time.time()
         global clients_APs, APs, evil_twins_list, packet_count, packet_sub58, packet_sub4, packet_datatype
         packet_count=packet_count+1
         if args.maximum:
              if args.noupdate:
                   if len(clients_APs) > int(args.maximum):
                        return
              else:
                   if len(clients_APs) > int(args.maximum):
                        with lock:
                             clients_APs = []
                             APs = []
                             evil_twins_list = []

##############################################################
#### Start type 0 Section -- This is the maintenance channel #
##############################################################
         if pkt.type in [1,2]:
              try:
                   if pkt.type == 1:
                        monchannel_local=packet_channel(pkt)
                   monchannel_local = 'Type 2 Packet'
                   packet_datatype=packet_datatype+1
                   clients_APs_add(clients_APs, pkt.addr1, pkt.addr2, str(mon_iface),monchannel_local)
              except:
                   del pkt
                   return
         if pkt.type in [0]:
              pkt.addr1 = pkt.addr1.lower()
              pkt.addr2 = pkt.addr2.lower()
              if args.accesspoint:
                   if args.accesspoint not in [pkt.addr1, pkt.addr2]:
                        return
              if pkt.subtype in [5,8]:
                   packet_sub58=packet_sub58+1
                #pkt_head = pkt[Dot11Elt]
                #cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                #                  "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
                   crypto = ''
                #while isinstance(pkt_head, Dot11Elt):
                #    if pkt_head.ID == 'vendor' and pkt.info.startswith('\x00P\xf2\x01\x01\x80'):
                #        crypto = ('WPA2')
                #    elif pkt_head.ID == 'vendor' and pkt.info.startswtih('\x00P\xf2\x01\x01\x00'):
                #        crypto = ('WPA')
                #    else:
                #        if 'privacy' in cap:      
                #             crypto = ("WEP")
                #        else:
                #             crypto = ("OPN")
                   try:
                        extra = pkt.notdecoded
                        rssi_local = -(256-ord(extra[-2:-1]))
                   except:
	                rssi_local = -100
#""" This will open the AP file for writing and etc"""
                   APs_add(clients_APs, APs, pkt, args.channel, args.world, str(rssi_local), crypto)
                   return
              if pkt.subtype == 4 and pkt.info != 'None':
                   packet_sub4=packet_sub4+1
                   evil_twin(evil_twins_list, pkt.addr2, pkt.info)
                   return
###############################################################
# This is the catch all for packets. It is important to note  #
# that returning the PacketHandler is critical                #
###############################################################
        return
    return PacketHandler
###############################################################
# END PACKET MONSTER FUNCTION                                 #
###############################################################

###############################################################
#Datastructure for Current Channel List                       #
###############################################################

def current_channel(current_channel_list, mon_iface, channel, channelDirection):
    for cur in current_channel_list:
        if mon_iface in cur[0]:
            current_channel_list.remove([cur[0],cur[1],cur[2]])
            return current_channel_list.append([mon_iface, channel, channelDirection])
    return current_channel_list.append([mon_iface, channel, channelDirection])

##############################################################
#Datastructure for Evil Twin List                            #
##############################################################

def evil_twin(evil_twin_list, addr2, ssid):
    for etb in evil_twin_list:
        if addr2 in etb and ssid in etb:
            t3=int(etb[2])+1
            evil_twin_list.remove([etb[0],etb[1],etb[2]])
            return evil_twin_list.append([addr2, ssid, str(t3)])
    count_int = '0'
    return evil_twin_list.append([addr2, ssid, count_int])
	

def packet_channel(pkt):
    try:
         packet_channel_info = str(ord(pkt[Dot11Elt:3].info))
         chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11','12','13','14', '32', '34', '36','38','40','42','44','46','48','50','52','54','56','58','60','62','64','100','102','104','108','110','112','114','116','118','120','122','124','126','128','130','132','134','136','138','140','142','144','149','151','153','155','157','159','161','165'] 
         #if packet_channel_info not in chans:
         #     packet_channel_info='unknown'
    except Exception as e:
        packet_channel_info='unknown'
    return packet_channel_info

###############################################################
#Datastructure for the AP list -- note that the packet is     #
# being stored in the structure                               #
###############################################################
def APs_add(clients_APs, APs, pkt, chan_arg, world_arg, rssi, packet_enc):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3
    ap_channel = packet_channel(pkt)
    if len(APs) == 0:
        with lock:
            return APs.append([bssid, ap_channel, ssid, rssi, packet_enc])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            return APs.append([bssid, ap_channel, ssid, rssi, packet_enc])
			
			
###############################################################
#Datastructure for the client to AP communications list       # 
###############################################################
def clients_APs_add(clients_APs, addr1, addr2, mon_iface, monchannel_local):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                return clients_APs.append([addr1, addr2, mon_iface, monchannel_local])
        else:
            AP_check(addr1, addr2, mon_iface)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2, mon_iface)
        else:
            with lock:
                return clients_APs.append([addr1, addr2, mon_iface, monchannel_local])


###############################################################
#Checking for duplicates before adding to the list of AP's    #
###############################################################
def AP_check(addr1, addr2, mon_iface):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                return clients_APs.append([addr1, addr2, mon_iface, ap[1], ap[2]])
				
				
###############################################################
#Clean up for SIGKILL                                         #
###############################################################
def stop(signal, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
        sys.exit('\n['+R+'!'+W+'] Closing')

###############################################################
#Funtion to call sniffer thread per interface                 #
###############################################################
def snifferThread(mon_iface):
    sniff(iface=str(mon_iface),store=0,prn=PacketMonster(mon_iface))

###############################################################
#Main execution area                                          #
###############################################################
if __name__=="__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')
    clients_APs = []
    APs = []
    evil_twins_list = []
    current_channel_list = []
    channel_offset='up'
    DN = open(os.devnull, 'w')
    lock = Lock()
    args = parse_args()
    monitor_on = None
    mon_iface_list = get_mon_iface(args)
    first_pass = 1
    gpsd.connect()
    # Start channel hopping
    for mon_iface in mon_iface_list:
	hop = Thread(target=channel_hop, args=(mon_iface, args, channel_offset))
        hop.daemon = True
        hop.start()
        snifferA = Thread(target=snifferThread, args=(mon_iface,))
        snifferA.start()
        snifferB = Thread(target=snifferThread, args=(mon_iface,))
        snifferB.start()
        if channel_offset == 'up':
            channel_offset = 'down'
        else:
            channel_offset = 'up'
            

    output_screen = Thread(target=output)
    output_screen.start()
    signal(SIGINT, stop)

    print "sniffing"
    
