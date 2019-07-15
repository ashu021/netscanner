#!/usr/bin/env python

import scapy.all as scapy
import argparse

print("NETWORK SCANNER")

def get_arguements():

    parser=argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="Target", help="enter ip range for scanning:" )
    options=parser.parse_args()
    return options

#scan function for scanning the result and returning the responses to print_result function
def scan(ip):

    arp_request_packet=scapy.ARP(pdst=ip)
    broadcast_mac=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_broadcast_packet=broadcast_mac/arp_request_packet
    answered_list=scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    clients_list=[]

    for element in answered_list:
        clients_dict={"IP":element[1].psrc,"MAC":element[1].hwsrc}
        clients_list.append(clients_dict)
      #  print(element[1].psrc + "\t\t" + element[1].hwsrc)
    #print(clients_list)
    return clients_list

#print_result function is for printing the result and for iterating
def print_result(result_list):
    print("--------------------------------")
    print("IP\t\t\tMAC ADDRESS\n--------------------------------")
    for client in result_list:
        print(client["IP"] + "\t\t" + client["MAC"])



options = get_arguements()
scan_result=scan(options.Target)
print_result(scan_result)
