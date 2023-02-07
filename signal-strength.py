#!/usr/bin/sudo /usr/bin/python3
from scapy.all import *
import os
import sys

class BeaconFrame():
    def __init__(self,raw_packet):
        self.bssid=[]
        self.fixed_param=""
        self.ssid=""
        self.raw_packet=raw_packet
        self.parseRadioTapHeader()
        self.parseBeaconFrame()
        self.parseParam()

    def parseRadioTapHeader(self):
        self.rt_header=self.raw_packet[:24]
        self.rt_header_revision=int(self.rt_header[0])
        self.rt_header_pad=int(self.rt_header[1])
        self.rt_header_len=int.from_bytes(self.rt_header[2:4],'little')
        self.present_flags=self.rt_header[4:12]
        self.flags=self.rt_header[12]
        self.data_rate=self.rt_header[13]
        self.ch_frequency=self.rt_header[14:16]
        self.ch_flags=self.rt_header[16:18]
        self.anthenna_signal=self.rt_header[18]
        self.anthenna_signal2=self.rt_header[22]
		
    def parseBeaconFrame(self):
        self.beacon_frame=self.raw_packet[self.rt_header_len:self.rt_header_len+24]
        self.frame_type=self.beacon_frame[0:2]
        self.duration=self.beacon_frame[2:4]
        self.dst_addr=":".join("%02X" % i for i in self.beacon_frame[4:10])
        self.src_addr=":".join("%02X" % i for i in self.beacon_frame[10:16])
        self.bss_id=":".join("%02X" % i for i in self.beacon_frame[16:22])
        self.seq_num=int.from_bytes(self.beacon_frame[22:24],'little')

    def parseParam(self):
        self.param=self.raw_packet[self.rt_header_len+24:]
        self.fixed_param=self.raw_packet[self.rt_header_len+24:self.rt_header_len+36]
        self.tagged_param=self.raw_packet[self.rt_header_len+36:]
        self.parseFixedParam()
        self.parseTaggedParam()

    def parseFixedParam(self):
        self.ts=int.from_bytes(self.fixed_param[:8],'little')
        self.intv=self.fixed_param[8:10]
        self.cap_info=int.from_bytes(self.fixed_param[10:12],'little')
    def parseTaggedParam(self):
        self.tag_num=self.tagged_param[0]
        self.tag_len=int(self.tagged_param[1])
        try:
            self.ssid=self.tagged_param[2:2+self.tag_len].decode('utf-8')
        except:
            return



def printInfo(bssdata):
    os.system("clear")
    print("%s %20s %8s"%("BSSID","PWR","SSID"))
    print("%s %8s     %8s"%(bssdata[0],bssdata[1]-256,bssdata[2]))


bssinfo={}

device=sys.argv[1]
mac=sys.argv[2]

def printPower(packet):
    #print(bytes(packet))
    raw_pkt=bytes(packet)
    frame_type=raw_pkt[24:26]
    if frame_type !=b"\x80\x00":
        return
    pkt=BeaconFrame(raw_pkt)
    if pkt.src_addr==mac:
        bssinfo=[pkt.src_addr,pkt.anthenna_signal,pkt.ssid]
        printInfo(bssinfo)
 


sniff(iface=device,prn=printPower,count=0)

