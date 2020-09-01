import io
import struct

PCAP_HEADER_LENGTH = 24

def PcapReader(filepath):
    pcap_file = open(filepath, 'rb')
    file_total_length = int(pcap_file.seek(0, io.SEEK_END))
    pcap_file.seek(PCAP_HEADER_LENGTH)
    pointer = PCAP_HEADER_LENGTH
    while pointer < file_total_length:
        second = struct.unpack('I', pcap_file.read(4))[0]
        microsecond = struct.unpack('I', pcap_file.read(4))[0]
        timestamp = float(str(second) + '.' + str(microsecond).zfill(6))
        packet_length = struct.unpack('I', pcap_file.read(4))[0] # Capture Length
        pcap_file.seek(4, io.SEEK_CUR) # actual length
        packet_body = pcap_file.read(packet_length)
        if struct.unpack('H', packet_body[12:14])[0] == 8:
            sip = '.'.join([str(i) for i in packet_body[26:30]])
            dip = '.'.join([str(i) for i in packet_body[30:34]])
            l4protocol = ''
            if packet_body[23] == 6:
                l4protocol = 'tcp'
            elif packet_body[23] == 17:
                l4protocol = 'udp'
            ip_header_length = (packet_body[14] & 0x0F) * 4
            sport = struct.unpack('!H', \
                packet_body[14 + ip_header_length:14 + ip_header_length + 2])[0]
            dport = struct.unpack('!H', \
                packet_body[14 + ip_header_length + 2:14 + ip_header_length + 4])[0]
            yield timestamp, packet_length, sip, dip, sport, dport, l4protocol
        pointer += 16 + packet_length
    pcap_file.close()