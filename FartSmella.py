import socket
import struct
import textwrap


TCP_PROTOCOL = 6
IPV4_PROTOCOL = 8
ICMP_PROTOCOL = 1
UDP_PROTOCOL = 17
class EthernetFrame:
    def __init__(self, destination_mac, source_mac, protocol, data) -> None:
        self.destinationMAC = destination_mac
        self.sourceMAC = source_mac
        self.protocol = protocol
        self.data = data

class Packet:
    def __init__(self, protocol, *args):
        self.data = args[-1]
        if(protocol == ICMP_PROTOCOL):
            self.type = args[0]
            self.code = args[1]
            self.checksum = args[2]
        elif(protocol == TCP_PROTOCOL):
            self.sourcePort = args[0]
            self.destinantionPort = args[1]
            self.sequenceNum = args[2]
            self.acknowledgmentNum = args[3]
            self.flags = args[4]
        elif(protocol == IPV4_PROTOCOL):
            self.version = args[0]
            self.headerLength = args[1]
            self.time2Live = args[2]
            self.protocol = args[3]
            self.sourceMAC = args[4]
            self.destinationMAC = args[5]
        elif(protocol == UDP_PROTOCOL):
            self.sourcePort = args[0]
            self.destinantionPort = args[1]
            self.sourcePort = args[2]

def unpack_ef(ef):
    destination_mac, source_mac, protocol = struct.unpack("! 6s 6s H", ef[:14])
    return format_mac(destination_mac), format_mac(source_mac), socket.htons(protocol), ef[14:]


def format_mac(mac):
    formatted_mac = map('{:02x}'.format, mac)
    return ':'.join(formatted_mac).upper()


def unpack_ipv4(data):
    vs_header_leng = data[0]
    vers = vs_header_leng >> 4
    head_leng = (vs_header_leng & 15) * 4
    ttl, protocol, source, target = struct.upack('! 8x B B 2x 4s 4s', data[:20])
    return vers, head_leng, ttl, protocol, format_ipv4(source), format_ipv4(target), data[head_leng:]


def format_ipv4(address):
    return '.'.join(map(str, address))


def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data [4:]


def unpack_tcp(data):
    (source_port, destination_port, seq, a_numb, off_res_flag) = struct.unpack('! H H L L H', data[:14])
    flags = []
    r = 64
    shift = 6
    offset = (off_res_flag >> 12) * 4
    for x in range(6):
        r = r / 2
        shift = shift - 1
        if(shift == 0):
            flags[x] = off_res_flag & r
        else:
            flags[x] = (off_res_flag & r) >> shift 
    return source_port, destination_port, seq, a_numb, flags, data[offset:]


def unpack_udp(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]


def format_multi(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



if __name__ == "__main__":
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        r_data, address = connection.recvfrom(65536)

        ef = EthernetFrame(unpack_ef(r_data))

        print("Ethernet Frame:")
        print(f"\t Destination: {ef.destinationMAC} Source: {ef.sourceMAC} Protocol: {ef.protocol}\n")

        if ef.protocol == IPV4_PROTOCOL:
            packet = Packet(IPV4_PROTOCOL, unpack_ipv4(ef.data))
            print("\t IPv4 Packet:")
            print(f"\t\t Version: {packet.version}, Header Length: {packet.headerLength}, Time to Live: {packet.time2Live}\n\t\t - Protocol: {packet.protocol}, Source: {packet.sourceMAC}, Target: {packet.destinationMAC}")

            if packet.protocol == ICMP_PROTOCOL:
                icmp_packet = Packet(ICMP_PROTOCOL, unpack_icmp(packet.data))
                print("\t ICMP Packet:")
                print(f"\t\t Type: {icmp_packet.type}, Code: {icmp_packet.code}, Checksum: {icmp_packet.checksum}")
                print("\t\t Data:")
                print(format_multi("\t\t\t - ", icmp_packet.data))
            elif packet.protocol == TCP_PROTOCOL:
                tcp_packet = Packet(TCP_PROTOCOL, unpack_tcp(ef.data))
                print("\t TCP Segment:")
                print(f"\t\t Source Port: {tcp_packet.sourcePort}, Destination Port: {tcp_packet.destinantionPort}")
                print(f"\t\t Sequence Number: {tcp_packet.sequenceNum}, Acknowledgement Number: {tcp_packet.acknowledgmentNum}")
                urg, ack, psh, rst, syn, fin = tcp_packet.flags
                print("\t Flags:")
                print(f"\t\t URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}")
                print("\t Data:")
                print(format_multi("\t\t ", tcp_packet.data))
            elif packet.protocol == UDP_PROTOCOL:
                udp_packet = Packet(UDP_PROTOCOL, unpack_udp(ef.data))
                print("\t UDP Segment:")
                print(f"\t\t Source Port: {udp_packet.sourcePort}, Destination Port: {udp_packet.destinantionPort}, Length: {udp_packet.headerLength}")
            else:
                print("\t Data:")
                print(format_multi("\t\t ", packet.data))
        else:
            print('Data:')
            print(format_multi("\t ", ef.data))