import socket
import struct
import textwrap


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

        destination_mac, source_mac, protocol, data = unpack_ef(r_data)

        print("Ethernet Frame:")
        print("\t Destination: {destination_mac} Source: {source_mac} Protocol: {protocol}\n")

        if protocol == 8:
            (vers, head_leng, ttl, protocol, source, target, data) = unpack_ipv4(data)
            print("\t IPv4 Packet:")
            print("\t\t Version: {vers}, Header Length: {head_leng}, Time to Live: {ttl}\n\t\t - Protocol: {protocol}, Source: {source}, Target: {target}")

            if protocol == 1:
                icmp_type, code, checksum, data = unpack_icmp(data)
                print("\t ICMP Packet:")
                print("\t\t Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                print("\t\t Data:")
                print(format_multi("\t\t\t - ", data))
            elif protocol == 6:
                (source_port, destination_port, seq, a_numb, flags, data) = unpack_tcp(data)
                print("\t TCP Segment:")
                print("\t\t Source Port: {source_port}, Destination Port: {destination_port}")
                print("\t\t Sequence Number: {seq}, Acknowledgement Number: {a_numb}")
                print("\t Flags:")
                print("\t\t URG: {flags[0]}, ACK: {flags[1]}, PSH: {flags[2]}, RST: {flags[3]}, SYN: {flags[4]}, FIN: {flags[5]}")
                print("\t Data:")
                print(format_multi("\t\t ", data))
            elif protocol == 17:
                source_port, destination_port, head_leng, data - unpack_udp(data)
                print("\t UDP Segment:")
                print("\t\t Source Port: {source_port}, Destination Port: {destination_port}, Length: {head_leng}")
            else:
                print("\t Data:")
                print(format_multi("\t\t ", data))
        else:
            print('Data:')
            print(format_multi("\t ",data))