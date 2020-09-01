'''
__author__ = 'ZebornDuan'

This script employs Pinball to extract event signatures for smart home IoT devices
in MonIoTr dataset.
'''

import glob as std_glob
from PcapReader import PcapReader
from pinball import Pinball

pinball = Pinball('Asia/Shanghai')

def get_overall_counter(pcap_list):
    overall_counter = []
    ip_packet_counter = {}
    tcp_packet_count, udp_packet_count = 0, 0 
    for pcap_file in pcap_list:
        packet_count = 0
        temperary_counter = {}
        # The timestamps of the event triggering are annotated in the file name.
        # It can be noticed that a period of traffic after the event triggering is 
        # missed in the traces and some PCAP files are nearly empty.
        # So we set the window size of distribution calculation as the duration of 
        # the packet capture for each event triggering in the dataset and ignore 
        # the files that have less than 20 effective IP packets.
        for t, l, sip, dip, _sport, _dport, l4protocol in PcapReader(pcap_file):
            packet_count += 1
            if l4protocol == 'tcp':
                tcp_packet_count += 1
            elif l4protocol == 'udp':
                udp_packet_count += 1
            if sip.startswith('192.168'):
                packet_label = (l, pinball.DIRECTION_IN)
                ip_packet_counter[sip] = ip_packet_counter.get(sip, 0) + 1
                if sip not in temperary_counter:
                    temperary_counter[sip] = {}
                temperary_counter[sip][packet_label] = \
                    temperary_counter[sip].get(packet_label, 0) + 1
            if dip.startswith('192.168'):
                packet_label = (l, pinball.DIRECTION_OUT)
                ip_packet_counter[dip] = ip_packet_counter.get(dip, 0) + 1
                if dip not in temperary_counter:
                    temperary_counter[dip] = {}
                temperary_counter[dip][packet_label] = \
                    temperary_counter[dip].get(packet_label, 0) + 1
        if packet_count > 20:
            overall_counter.append(temperary_counter)
    if not ip_packet_counter:
        return overall_counter, '', tcp_packet_count, udp_packet_count
    # the IP address that generates the most packets in the traffic traces is inferred as
    # the IP address of the smart home IoT device. And it is assumed that the same device
    # always uses the same IP address.

    # Although this assumption is true for most devices in MonIoTr dataset, there exist 
    # some exceptional devices, such as TPLink Plug, which may use more than one IP address
    # in the traffic traces for the same event(192.168.20.227, 192.168.20.229...).  
    possible_device_ip = sorted([(v, k) for k, v in ip_packet_counter.items()], \
        key=lambda x: -x[0])[0][1]
    return overall_counter, possible_device_ip, tcp_packet_count, udp_packet_count

def extract_signatures(overall_counter, device_ip):
    event_times = len(overall_counter)
    print(event_times)
    if event_times <= 3:
        return None
    packet_counter, packet_occurrence = {}, {}
    for counter in overall_counter:
        for ip, c in counter.items():
            if ip not in packet_counter:
                packet_counter[ip] = {}
                packet_occurrence[ip] = {}
            for packet_label, n in c.items():
                packet_counter[ip][packet_label] = packet_counter[ip].get(\
                    packet_label, 0) + n
            for packet_label in c.keys():
                packet_occurrence[ip][packet_label] = packet_occurrence[\
                    ip].get(packet_label, 0) + 1
    pinball.occurrence_low_bound = int(event_times * 0.9)
    pinball.occurrence_up_bound = int(event_times * 1.1)
    s = pinball.get_signature(packet_counter, packet_occurrence, device_ip)
    return s

def run_all_device_event(base):
    device_list = std_glob.glob(base + '**/')
    for device in device_list:
        event_list = std_glob.glob(device + '**/')
        for event in event_list:
            pcap_list = std_glob.glob(event + '*.pcap')
            # ignore the events with a limited number (3 or less) of samples
            if len(pcap_list) <= 3:
                continue
            overall_counter, ip, tcp_c, udp_c = get_overall_counter(pcap_list)
            device_name = device.split('/')[-2]
            event_name = event.split('/')[-2]
            main_l4_protocol = 'UDP' if udp_c > tcp_c else 'TCP'
            signature = extract_signatures(overall_counter, ip)
            print(device_name, event_name, ip, main_l4_protocol)
            print(signature)
            print('------------')


if __name__ == '__main__':
    run_all_device_event('./MonIoTr/uk/')
