import argparse
import os
import socket
import struct
import sys
import time

import select

ICMP_ECHO = 8
ICMP_ECHO_REPLY = 0
ICMP_TIME_EXCEEDED = 11
MIN_SLEEP = 1000

timer = time.time

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('dest_host')
    parser.add_argument('-c', '--count', required=False, nargs='?', default=3, type=int, metavar='Number Of Packets')
    parser.add_argument('-m', '--maxhops', required=False, nargs='?', default=64, type=int, metavar='Max Hops')
    parser.add_argument('-a', '--max_ttl', required=False, nargs='?', default=10, type=int, metavar='Max TTL')
    parser.add_argument('-l', '--ttl', required=False, nargs='?', default=1, type=int, metavar='Start TTL')
    parser.add_argument('-t', '--timeout', required=False, nargs='?', default=1000, type=int, metavar='Timeout(ms)')
    parser.add_argument('-p', '--packet_size', required=False, nargs='?', default=55, type=int,
                        metavar='Packet Size')

    return parser


def calculate_checksum(packet):
    countTo = (len(packet) // 2) * 2

    count = 0
    sum = 0

    while count < countTo:
        if sys.byteorder == "little":
            loByte = packet[count]
            hiByte = packet[count + 1]
        else:
            loByte = packet[count + 1]
            hiByte = packet[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    if countTo < len(packet):
        sum += packet[count]

        # sum &= 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum & 0xffff
    answer = socket.htons(answer)

    return answer


def check_ip_validation(hostname):
    ip_parts = hostname.strip().split('.')
    if len(ip_parts) != 4:
        return False

    for part in ip_parts:
        try:
            if int(part) < 0 or int(part) > 255:
                return False
        except ValueError:
            return False

    return True


def convert_hostname_to_ip(hostname):
    if check_ip_validation(hostname):
        return hostname
    return socket.gethostbyname(hostname)


class Traceroute:
    def __init__(self, dest_host, count_of_packets, packet_size, max_hops, timeout, ttl, max_ttl):
        self.dest_host = dest_host
        self.count_of_packets = count_of_packets
        self.packet_size = packet_size
        self.max_hops = max_hops
        self.timeout = timeout
        self.identifier = os.getpid() & 0xffff
        self.seq_no = 0
        self.delays = []
        self.prev_sender_hostname = ""

        self.ttl = ttl
        try:
            self.destination_ip = convert_hostname_to_ip(dest_host)
        except socket.gaierror:
            print("traceroute: unknown host {}".format(self.dest_host))


    def print_timeout(self):
        if self.seq_no == 1:
            if self.ttl < max_ttl:
                print(" {}  ".format(self.ttl), end="")
            else:
                print("{}  ".format(self.ttl), end="")
        print("* ", end="")
        if self.seq_no == self.count_of_packets:
            print()

    def print_trace(self, delay, ip_header):

        ip = socket.inet_ntoa(struct.pack('!I', ip_header['Source_IP']))
        try:
            sender_hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            sender_hostname = ip

        if self.prev_sender_hostname != sender_hostname:
            if self.ttl < 10:
                print(" {}  {} ({}) {:.3f}ms ".format(self.ttl, sender_hostname, ip, delay), end="")
            else:
                print("{}  {} ({}) {:.3f}ms ".format(self.ttl, sender_hostname, ip, delay), end="")
            self.prev_sender_hostname = sender_hostname

        else:
            print("{:.3f} ms ".format(delay), end="")

        if self.seq_no == self.count_of_packets:
            print()
            self.prev_sender_hostname = ""
            if MIN_SLEEP > delay:
                time.sleep((MIN_SLEEP - delay) / 1000)

    def header_to_dict(self, keys, packet, struct_format):
        values = struct.unpack(struct_format, packet)
        return dict(zip(keys, values))

    def start_traceroute(self):

        icmp_header = None
        while self.ttl <= self.max_hops:
            self.seq_no = 0
            try:
                for i in range(self.count_of_packets):
                    icmp_header = self.tracer()

            except KeyboardInterrupt:  # handles Ctrl+C
                break

            self.ttl += 1
            if icmp_header is not None:
                if icmp_header['type'] == ICMP_ECHO_REPLY:
                    break

    def tracer(self):

        try:
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
            icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)

        except socket.error as err:
            if err.errno == 1:
                print("Operation not permitted: ICMP messages can only be sent from a process running as root")
            else:
                print("Error: {}".format(err))

            sys.exit()

        self.seq_no += 1
        if self.ttl == 1 and self.seq_no == 1:
            print("traceroute to {} ({}), {} hops max, {} byte packets".format(self.dest_host,
                                                                               self.destination_ip,
                                                                               self.max_hops, self.packet_size))

        sent_time = self.send_icmp_echo(icmp_socket)

        if sent_time is None:
            return

        receive_time, icmp_header, ip_header = self.receive_icmp_reply(icmp_socket)

        icmp_socket.close()
        if receive_time:
            delay = (receive_time - sent_time) * 1000.0
            self.print_trace(delay, ip_header)

        return icmp_header

    def send_icmp_echo(self, icmp_socket):

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, self.identifier, self.seq_no)

        start_value = 65
        payload = []
        for i in range(start_value, start_value + self.packet_size):
            payload.append(i & 0xff)

        data = bytes(payload)
        checksum = calculate_checksum(header + data)
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.identifier, self.seq_no)

        packet = header + data

        send_time = timer()
        try:
            icmp_socket.sendto(packet, (self.dest_host, 1))

        except socket.error as err:
            print("General error: %s", err)
            icmp_socket.close()
            return

        return send_time

    def receive_icmp_reply(self, icmp_socket):

        timeout = self.timeout / 1000

        while True:
            # started_select = time.time()
            inputReady, _, _ = select.select([icmp_socket], [], [], timeout)
            # how_long_in_select = time.time() - started_select
            receive_time = timer()

            if not inputReady:  # timeout
                self.print_timeout()
                return None, None, None

            packet_data, address = icmp_socket.recvfrom(2048)

            icmp_keys = ['type', 'code', 'checksum', 'identifier', 'sequence number']
            values = struct.unpack(packet_data[20:28], "!BBHHH")
            icmp_header = dict(zip(icmp_keys, values))

            ip_keys = ['VersionIHL', 'Type_of_Service', 'Total_Length', 'Identification', 'Flags_FragOffset', 'TTL',
                       'Protocol', 'Header_Checksum', 'Source_IP', 'Destination_IP']

            values = struct.unpack( packet_data[:20], "!BBHHHBBHII")
            ip_header = dict(zip(ip_keys, values))
            return receive_time, icmp_header, ip_header


def traceroute(dest_host, count_of_packets=3, packet_size=52, max_hops=64, timeout=1000, ttl=1, max_ttl=10):
    t = Traceroute(dest_host, count_of_packets, packet_size, max_hops, timeout, ttl, max_ttl)
    t.start_traceroute()


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args(sys.argv[1:])
    dest_host = args.dest_host
    timeout = args.timeout
    packet_size = args.packet_size
    count = args.count
    max_hops = args.maxhops
    ttl = args.ttl
    max_ttl = args.max_ttl
    traceroute(dest_host, count, packet_size, max_hops, timeout, ttl, max_ttl)
