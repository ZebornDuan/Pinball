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
            yield timestamp, packet_length, sip, dip
        pointer += 16 + packet_length

if __name__ == '__main__':
    count = 0
    for t, l, sip, dip in PcapReader('./PingPong/evaluation-datasets/local-phone/standalone/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap'):
        print(t, l, sip, dip)
        count += 1
        if count == 100:
            break
