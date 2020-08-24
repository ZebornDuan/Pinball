import arrow
import datetime
import math
import scapy.all as scapy
from collections import deque, namedtuple
from scapy.utils import PcapReader

TCounter = namedtuple('TCounter', ['start_time', 'counter'])

class SignaturePinball(object):
    def __init__(self):
        self._range_map = {}
        self._packet_label_map = {}

    def from_no_range_signature(self, s):
        self._packet_label_map = s
        return self

    def from_distribution(self, distribution, range_map):
        self._packet_label_map = distribution
        self._range_map = range_map
        return self

    def add_length_term(self, label, p):
        self._packet_label_map[label] = p

    def add_range_term(self, label, p):
        range_label = '[' + str(label[0]) + '-' + str(label[-1]) + ']'
        for packet_label in label:
            self._range_map[packet_label] = range_label
        self._packet_label_map[range_label] = p

    def get(self, key, default=None):
        return self._packet_label_map.get(self._range_map.get(key, key), default)

    def __getitem__(self, key):
        return self._packet_label_map[self._range_map.get(key, key)]

    def __contains__(self, item):
        return self._range_map.get(item, item) in self._packet_label_map

    def __repr__(self):
        return self._packet_label_map.__repr__()

    def keys(self):
        return self._packet_label_map.keys()

    def packet_keys(self):
        return list(self._packet_label_map.keys()) + list(self._range_map.keys())

    def values(self):
        return self._packet_label_map.values()

    def items(self):
        return self._packet_label_map.items()

    def get_distribution_from_counter(self, counter):
        total_packet_count = sum(counter.values())
        d = {k: 0 for k in self.keys()}
        if total_packet_count != 0:
            for packet_label, n in counter.items():
                k = self._range_map.get(packet_label, packet_label)
                if k in self._packet_label_map:
                    d[k] += n
            for k in d.keys():
                d[k] /= total_packet_count
        return SignaturePinball().from_distribution(d, self._range_map)


class Pinball(object):
    def __init__(self, timezone):
        self.interval = 10
        self.timezone = timezone
        self.DIRECTION_IN = 0x00
        self.DIRECTION_OUT = 0x01
        self.event_trigger_times = 50
        self.occurrence_low_bound = 45
        self.occurrence_up_bound = 55

    @staticmethod
    def calculate_KL_divergence(d1, d2):
        e = 0.0
        epsilon = 1e-9
        for x, p in d1.items():
            q = d2[x] if d2.get(x, 0) else epsilon
            e += p * math.log(p, 2) - p * math.log(q, 2)
        if e < epsilon:
            e = 0.0
        return e

    @staticmethod
    def calculate_hellinger_distance(d1, d2):
        s1 = set(d1.keys())
        s2 = set(d2.keys())
        s = s1 | s2
        d = 0.0
        for packet_header in s:
            p1 = d1.get(packet_header, 0.0)
            p2 = d2.get(packet_header, 0.0)
            d += (math.sqrt(p1) - math.sqrt(p2)) ** 2
        d = math.sqrt(d) / math.sqrt(2)
        return d

    @staticmethod
    def calculate_occurrence_discrepancy(d1, d2):
        epsilon = 1e-9
        d = 1.0
        t = sum([1 / p for p in d1.values()])
        weight = {k: 1 / p / t for k, p in d1.items()}
        for x in d1.keys():
            if d2[x]:
                d -= weight[x]
        if d < epsilon:
            d = 0.0
        return d

    @staticmethod
    def calculate_all_metrics(d1, d2):
        y1 = Pinball.calculate_hellinger_distance(d1, d2)
        y2 = Pinball.calculate_KL_divergence(d1, d2)
        y3 = Pinball.calculate_occurrence_discrepancy(d1, d2)
        return y1, y2, y3

    '''
    * This function converts the timestamp strings in PingPong dataset to local timestamps.

    * @Parameter: tstring: timestamp string in .timestamps files in PingPong dataset
    * @Patameter: zone_offset: timezone offset to ZONE_ID_LOS_ANGELES according to your local time.

    * @Return: local timestamp value
    '''
    def format_time(self, tstring):
        # original format: MM/dd/yyyy hh:mm:ss (A|P)M
        # e.g. 12/15/2019 11:29:38 PM
        MM, dd, yyyy = int(tstring[0:2]), int(tstring[3:5]), int(tstring[6:10])
        hh, mm, ss = int(tstring[11:13]), int(tstring[14:16]), int(tstring[17:19]) 
        ampm = tstring[20:22]
        t = arrow.get(yyyy, MM, dd, hh, hh, ss).replace(tzinfo='America/Los_Angeles')
        t1 = arrow.get(t.year, t.month, t.day, t.hour, t.minute, t.second)
        t_ = t.to(tz=self.timezone)
        t2 = arrow.get(t_.year, t_.month, t_.day, t_.hour, t_.minute, t_.second)
        timeoffset = t2 - t1
        pm_offset = datetime.timedelta(hours=12)
        # in 12 hour system, 12:30 PM should be written as 00:30 PM, denoting the time at noon
        if hh == 12:
            hh = 0
        d = datetime.datetime(yyyy, MM, dd, hh, mm, ss)
        if ampm == 'PM':
            d = d + pm_offset
        d = d + timeoffset
        # print(d.timestamp())
        return d.timestamp()

    def _get_overall_counter(self, pcapfile, tsfile):
        event_timestring = open(tsfile, 'r').readlines()
        event_timestamps = [self.format_time(tstring.strip()) for tstring in event_timestring]
        index = 0
        overall_counter = {'even': {}, 'odd': {}}

        def on_new_packet(index, sip, dip, length):
            on_off = 'even' if index % 2 == 0 else 'odd'
            instance_label = (sip, index)
            direction = self.DIRECTION_OUT
            if instance_label not in overall_counter[on_off]:
                overall_counter[on_off][instance_label] = {}
            packet_label = (length, direction)
            overall_counter[on_off][instance_label][packet_label] = \
                overall_counter[on_off][instance_label].get(packet_label, 0) + 1
            
            instance_label = (dip, index)
            direction = self.DIRECTION_IN
            if instance_label not in overall_counter[on_off]:
                overall_counter[on_off][instance_label] = {}
            packet_label = (length, direction)
            overall_counter[on_off][instance_label][packet_label] = \
                overall_counter[on_off][instance_label].get(packet_label, 0) + 1

        with PcapReader(pcapfile) as traffic_trace:
            for packet in traffic_trace:
                if scapy.IP in packet:
                    t = packet.time
                    l = packet.wirelen
                    sip, dip = packet[scapy.IP].src, packet[scapy.IP].dst
                    if 0 < t - event_timestamps[index] <= self.interval:
                        on_new_packet(index, sip, dip, l)
                    elif t - event_timestamps[index] > self.interval:
                        index += 1
                        if index >= len(event_timestamps):
                            break
        return overall_counter

    def _get_signature(self, packet_counter, packet_occurrence, device_ip):
        high_frequency_packets, event_signature = set(), {}
        if device_ip not in packet_occurrence:
            return None
        for label, occurrence in packet_occurrence[device_ip].items():
            if self.occurrence_low_bound <= occurrence <= self.occurrence_up_bound:
                high_frequency_packets.add(label)
        for l in high_frequency_packets:
            packet_occurrence[device_ip].pop(l)
        range_label_occurrence_sum = 0
        all_packet_labels = sorted(list(packet_occurrence[device_ip].keys()))
        i, r, range_lables = 1, [all_packet_labels[0]], []
        while i < len(all_packet_labels):
            if all_packet_labels[i][1] == all_packet_labels[i - 1][1] and \
                all_packet_labels[i][0] - all_packet_labels[i - 1][0] <= 1:
                r.append(all_packet_labels[i])
            else:
                occurrence_sum = sum([packet_occurrence[device_ip][pl] for pl in r])
                if self.occurrence_low_bound <= occurrence_sum <= self.occurrence_up_bound:
                    range_label_occurrence_sum += occurrence_sum
                    range_lables.append((r, occurrence_sum))
                r = [all_packet_labels[i]]
            i += 1
        packet_sum = sum([packet_counter[device_ip][l] for l in high_frequency_packets])
        packet_sum += range_label_occurrence_sum
        for l in high_frequency_packets:
            event_signature[l] = packet_counter[device_ip][l] / packet_sum
        event_signature = SignaturePinball().from_no_range_signature(event_signature)
        for rl, occurrence in range_lables:
            p = occurrence / packet_sum
            event_signature.add_range_term(rl, p)
        return event_signature

    def extract_event_signatures(self, pcap_file, timestamp_file, device_ip):
        packet_counter = {'even': {}, 'odd': {}}
        packet_occurrence = {'even': {}, 'odd': {}}
        overall_counter = self._get_overall_counter(pcap_file, timestamp_file)
        packet_counter = {'even': {}, 'odd': {}}
        packet_occurrence = {'even': {}, 'odd': {}}
        for k, v in overall_counter.items():
            for label, c in v.items():
                local_ip = label[0]
                if local_ip not in packet_counter[k]:
                    packet_counter[k][local_ip] = {}
                    packet_occurrence[k][local_ip] = {}
                for packet_label, n in c.items():
                    packet_counter[k][local_ip][packet_label] = packet_counter[k][local_ip].get(\
                        packet_label, 0) + n
                for packet_label in c.keys():
                    packet_occurrence[k][local_ip][packet_label] = packet_occurrence[k][\
                        local_ip].get(packet_label, 0) + 1
        on_event_signature = \
            self._get_signature(packet_counter['even'], packet_occurrence['even'], device_ip)
        off_event_signature = \
            self._get_signature(packet_counter['odd'], packet_occurrence['odd'], device_ip)
        print(on_event_signature, off_event_signature)
        return on_event_signature, off_event_signature

    def validate_signature(self, pcapfile, on_event_signature, off_event_signature):
        ip_queue_map, ip_temperary_counter_map, ip_result_map, ip_match_map = {}, {}, {}, {}
        current_time, match, last_match_time = 0, 0, 0
        traffic_trace = PcapReader(pcapfile)
        for packet in traffic_trace:
            if current_time == 0:
                # initialize current time
                current_time = int(packet.time)
            if scapy.IP in packet:
                t = packet.time
                l = packet.wirelen
                sip, dip = packet[scapy.IP].src, packet[scapy.IP].dst
                while int(t) > current_time:
                    for ip, counter in ip_temperary_counter_map.items():
                        if ip not in ip_queue_map:
                            ip_queue_map[ip] = deque()
                            ip_result_map[ip] = {
                                'X': [], 
                                'Y1_1': [], 'Y1_2': [], 'Y1_3': [], 
                                'Y2_1': [], 'Y2_2': [], 'Y2_3': [],
                            }
                        tCounter = TCounter(\
                            start_time=current_time, counter=counter)
                        ip_queue_map[ip].append(tCounter)
                        if len(ip_queue_map[ip]) == self.interval:
                            ip_result_map[ip]['X'].append(ip_queue_map[ip][0].start_time)
                            d1, d2 = {}, {}
                            for c in ip_queue_map[ip]:
                                for packet_label in on_event_signature.packet_keys():
                                    d1[packet_label] = d1.get(packet_label, 0) \
                                        + c.counter.get(packet_label, 0)
                                for packet_label in off_event_signature.packet_keys():
                                    d2[packet_label] = d2.get(packet_label, 0) \
                                        + c.counter.get(packet_label, 0)
                            d1 = on_event_signature.get_distribution_from_counter(d1)
                            d2 = off_event_signature.get_distribution_from_counter(d2)
                            y1_1, y1_2, y1_3 = self.calculate_all_metrics(on_event_signature, d1)
                            y2_1, y2_2, y2_3 = self.calculate_all_metrics(off_event_signature, d2)
                            if (y2_1 < 0.25 and y2_2 < 1.4 and y2_3 < 0.15) or (y1_1 < 0.25 and y1_2 < 1.4 and y1_3 < 0.15):
                                mt = int(t)
                                if ip in ip_match_map:
                                    if mt - ip_match_map[ip]['last_match_time'] > self.interval:
                                        ip_match_map[ip]['times'] += 1
                                        print(ip_match_map[ip]['times'], mt, y1_1, y1_2, y1_3, y2_1, y2_2, y2_3)
                                    ip_match_map[ip]['last_match_time'] = mt
                                else:
                                    ip_match_map[ip] = {'times': 1, 'last_match_time': mt}
                            ip_result_map[ip]['Y1_1'].append(y1_1)
                            ip_result_map[ip]['Y1_2'].append(y1_2)
                            ip_result_map[ip]['Y1_3'].append(y1_3)
                            ip_result_map[ip]['Y2_1'].append(y2_1)
                            ip_result_map[ip]['Y2_2'].append(y2_2)
                            ip_result_map[ip]['Y2_3'].append(y2_3)
                            ip_queue_map[ip].popleft()
                        ip_temperary_counter_map[ip] = {}
                    current_time += 1
                if int(t) == current_time:
                    if sip not in ip_temperary_counter_map:
                        ip_temperary_counter_map[sip] = {}
                    ip_temperary_counter_map[sip][(l, self.DIRECTION_OUT)] = \
                        ip_temperary_counter_map[sip].get((l, self.DIRECTION_OUT), 0) + 1
                    
                    if dip not in ip_temperary_counter_map:
                        ip_temperary_counter_map[dip] = {}
                    ip_temperary_counter_map[dip][(l, self.DIRECTION_IN)] = \
                        ip_temperary_counter_map[dip].get((l, self.DIRECTION_IN), 0) + 1
        return ip_match_map                    

if __name__ == '__main__':
    pinball = Pinball('Asia/Shanghai')
    # pcapfile = './PingPong/evaluation-datasets/local-phone/standalone/st-plug/wlan1/st-plug.wlan1.local.pcap'
    # tsfile = './PingPong/evaluation-datasets/local-phone/standalone/st-plug/timestamps/st-plug-nov-12-2018.timestamps'
    # v_pcapfile = './PingPong/evaluation-datasets/local-phone/smarthome/st-plug/wlan1/st-plug.wlan1.detection.pcap'
    pcapfile = './PingPong/evaluation-datasets/local-phone/standalone/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap'
    tsfile = './PingPong/evaluation-datasets/local-phone/standalone/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps'
    v_pcapfile = './PingPong/evaluation-datasets/local-phone/smarthome/dlink-plug/wlan1/dlink-plug.wlan1.detection.pcap'
    pcapfile = './PingPong/evaluation-datasets/local-phone/standalone/nest-thermostat/wlan1/nest-thermostat.wlan1.local.pcap'
    tsfile = './PingPong/evaluation-datasets/local-phone/standalone/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps'
    v_pcapfile = './PingPong/evaluation-datasets/local-phone/smarthome/nest-thermostat/wlan1/nest-thermostat.wlan1.detection.pcap'

    on_s, off_s = pinball.extract_event_signatures(pcapfile, tsfile, '192.168.1.246')
    import pickle
    # f = open('st-plug.pkl', 'rb')
    # f = open('d-link-plug.pkl', 'rb')
    f = open('nest-thermostat.pkl', 'wb')

    pickle.dump((on_s, off_s), f)
    # on_s, off_s = pickle.load(f)
    f.close()
    print(pinball.validate_signature(v_pcapfile, on_s, off_s))