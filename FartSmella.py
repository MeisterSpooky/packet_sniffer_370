from os import system
import socket
import struct
import textwrap
from time import sleep


TCP_PROTOCOL = 6
IPV4_PROTOCOL = 8
ICMP_PROTOCOL = 1
UDP_PROTOCOL = 17

class EthernetFrame:
    def __init__(self, info):
        self.destinationMAC = info[0]
        self.sourceMAC = info[1]
        self.protocol = info[2]
        self.data = info[3]

class Packet:
    def __init__(self, protocol, info):
        self.protocol = protocol
        self.data = info[-1]
        if(protocol == ICMP_PROTOCOL):
            self.type = info[0]
            self.code = info[1]
            self.checksum = info[2]
        elif(protocol == TCP_PROTOCOL):
            self.sourcePort = info[0]
            self.destinantionPort = info[1]
            self.sequenceNum = info[2]
            self.acknowledgmentNum = info[3]
            self.flags = info[4]
        elif(protocol == IPV4_PROTOCOL):
            self.version = info[0]
            self.headerLength = info[1]
            self.time2Live = info[2]
            self.protocol = info[3]
            self.sourceMAC = info[4]
            self.destinationMAC = info[5]
        elif(protocol == UDP_PROTOCOL):
            self.sourcePort = info[0]
            self.destinantionPort = info[1]
            self.headerLength = info[2]

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
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return vers, head_leng, ttl, protocol, format_ipv4(source), format_ipv4(target), data[head_leng:]


def format_ipv4(address):
    return '.'.join(map(str, address))


def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data [4:]


def unpack_tcp(data):
    (source_port, destination_port, seq, a_numb, off_res_flag) = struct.unpack('! H H L L H', data[:14])
    
    offset = (off_res_flag >> 12) * 4
    flag_urg = (off_res_flag & 32) >> 5
    flag_ack = (off_res_flag & 16) >> 5
    flag_psh = (off_res_flag & 8) >> 5
    flag_rst = (off_res_flag & 4) >> 5
    flag_syn = (off_res_flag & 2) >> 5
    flag_fin = (off_res_flag & 32) >> 5

    flags = [flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin]

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

def Title():
    print("\t /$$$$$$$$                   /$$      /$$$$$$            /$$  /$$$$$$   /$$$$$$                   \n\
        | $$_____/                  | $$     /$$__  $$          |__/ /$$__  $$ /$$__  $$                  \n\
        | $$    /$$$$$$   /$$$$$$  /$$$$$$  | $$  \__/ /$$$$$$$  /$$| $$  \__/| $$  \__//$$$$$$   /$$$$$$ \n\
        | $$$$$|____  $$ /$$__  $$|_  $$_/  |  $$$$$$ | $$__  $$| $$| $$$$    | $$$$   /$$__  $$ /$$__  $$\n\
        | $$__/ /$$$$$$$| $$  \__/  | $$     \____  $$| $$  \ $$| $$| $$_/    | $$_/  | $$$$$$$$| $$  \__/\n\
        | $$   /$$__  $$| $$        | $$ /$$ /$$  \ $$| $$  | $$| $$| $$      | $$    | $$_____/| $$      \n\
        | $$  |  $$$$$$$| $$        |  $$$$/|  $$$$$$/| $$  | $$| $$| $$      | $$    |  $$$$$$$| $$      \n\
        |__/   \_______/|__/         \___/   \______/ |__/  |__/|__/|__/      |__/     \_______/|__/      \n\
                                                                                                        ")
def Menu():
    clear_screen()
    print(f"Welcome to the wireless Fart Smeller")
    print(f"What would you like to do?")
    print("\t1 - Sniff Farts")
    print("\t2 - View Credits")
    print("\tq - Quit")
    return input("Selection: ")

def clear_screen():
    _ = system('clear')


if __name__ == "__main__":   

    Title()
    sleep(2)
    clear_screen()
    selection = 0

    while selection != "q":

        selection = Menu()

        if selection == "1":
            
            connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            tb_written =[]
            f = open('farts_sniffed.log', 'w')

            while True:
                r_data, address = connection.recvfrom(65536)

                ef = EthernetFrame(unpack_ef(r_data))

                tb_written.append("Ethernet Frame:")
                tb_written.append(f"\t Destination: {ef.destinationMAC} Source: {ef.sourceMAC} Protocol: {ef.protocol}\n")

                if ef.protocol == IPV4_PROTOCOL:
                    packet = Packet(IPV4_PROTOCOL, unpack_ipv4(ef.data))
                    tb_written.append("\t IPv4 Packet:")
                    tb_written.append(f"\t\t Version: {packet.version}, Header Length: {packet.headerLength}, Time to Live: {packet.time2Live}\n\t\t - Protocol: {packet.protocol}, Source: {packet.sourceMAC}, Target: {packet.destinationMAC}")

                    if packet.protocol == ICMP_PROTOCOL:
                        icmp_packet = Packet(ICMP_PROTOCOL, unpack_icmp(packet.data))
                        tb_written.append("\t ICMP Packet:")
                        tb_written.append(f"\t\t Type: {icmp_packet.type}, Code: {icmp_packet.code}, Checksum: {icmp_packet.checksum}")
                        tb_written.append("\t\t Data:")
                        tb_written.append(format_multi("\t\t\t - ", icmp_packet.data))
                    elif packet.protocol == TCP_PROTOCOL:
                        tcp_packet = Packet(TCP_PROTOCOL, unpack_tcp(ef.data))
                        tb_written.append("\t TCP Segment:")
                        tb_written.append(f"\t\t Source Port: {tcp_packet.sourcePort}, Destination Port: {tcp_packet.destinantionPort}")
                        tb_written.append(f"\t\t Sequence Number: {tcp_packet.sequenceNum}, Acknowledgement Number: {tcp_packet.acknowledgmentNum}")
                        urg, ack, psh, rst, syn, fin = tcp_packet.flags
                        tb_written.append("\t Flags:")
                        tb_written.append(f"\t\t URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}")
                        tb_written.append("\t Data:")
                        tb_written.append(format_multi("\t\t ", tcp_packet.data))
                    elif packet.protocol == UDP_PROTOCOL:
                        udp_packet = Packet(UDP_PROTOCOL, unpack_udp(ef.data))
                        tb_written.append("\t UDP Segment:")
                        tb_written.append(f"\t\t Source Port: {udp_packet.sourcePort}, Destination Port: {udp_packet.destinantionPort}, Length: {udp_packet.headerLength}")
                    else:
                        tb_written.append("\t Data:")
                        tb_written.append(format_multi("\t\t ", packet.data))
                else:
                    tb_written.append('Data:')
                    tb_written.append(format_multi("\t ", ef.data))
                
                for line in tb_written:
                    f.write(line)
                    f.write('\n')
            
            f.close()
        if selection == "2":
            clear_screen()
            Title()
            print("By javi ty and ticus :)")
            input("--Press any key to continue.--")
        
    clear_screen()
    print("come back soon ;* <3 !")
    quit()