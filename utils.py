# __author__ = ZebornDuan

import glob as std_glob
import os


'''
* This function extracts the ip addresses of IoT devices and smartphones in the PingPong Dataset 
* by text analysis.

* The input file is `execute_signature_generation.sh` in PingPong PacketLevelSignatureExtractor
* project. The input parameter should be the path to the file.

* @Return: a map structure that can be serialized in json format.
* key: timestamps file name (unique for the same device in different datasets)
* value: [ip addresses]
'''
def get_device_ip_map(path_to_ESG_file):
    f = open(path_to_ESG_file, 'r')
    line = f.readline()
    TIMESTAMP_LABEL = 0x00
    DEVICE_IP_LABEL = 0x01
    last_line_label = DEVICE_IP_LABEL
    ts_file_name, device_ip, device_ip_map = '', '', {}
    while line:
        if line.startswith('TIMESTAMP_FILE'):
            ts_file_name = line.split('/')[-1].strip()[:-1]
            last_line_label = TIMESTAMP_LABEL
            device_ip_map[ts_file_name] = []
        if line.startswith('DEVICE_IP'):
            device_ip = line.strip()[11:-1]
            device_ip_map[ts_file_name].append(device_ip)
            last_line_label = DEVICE_IP_LABEL
        line = f.readline()
    # print(device_ip_map)
    return device_ip_map

'''
/PingPong
    /evaluation-datasets/
        /ifttt
            /smarthome
                /...
            /standalone
                /[$DEVICE_TYPE]
                    /timestamps
                        /*.timestamps
                    /wlan1 [? eth0 ? eth1]
                        /*.pcap
        /local-phone
            /...
        /public-dataset
            /...
        /remote-phone
            /...
        /same-vendor
            /...
'''
def get_parameter_setting(dataset_base, device_ip_map):
    parameter_setting_list = []
    group = std_glob.glob(dataset_base + '/**/')
    TRAIN_BASE = 'standalone/**/'
    possible_data_directory = ['wlan1', 'eth0', 'eth1']
    for g in group:
        device_list = std_glob.glob(g + TRAIN_BASE)
        for d in device_list:
            if os.path.exists(d + 'timestamps/'):
                ts_file_path = std_glob.glob(d + 'timestamps/*.timestamps')[0]
                ts_file_name = ts_file_path.split('/')[-1]
                device_ip = device_ip_map.get(ts_file_name, [])
                parameter_setting = {
                    'train_tsfile': ts_file_path,
                    'device_ip': device_ip, # IoT device or local phone
                    'train_input_pcap': [],
                    'test_input_pcap': [],
                }
                for pdd in possible_data_directory:
                    if os.path.exists(d + pdd + '/'):
                        pcap_file_path = std_glob.glob(d + pdd + '/*.pcap')[0]
                        parameter_setting['train_input_pcap'].append(pcap_file_path)
                test_base = d.replace('standalone', 'smarthome')
                for pdd in possible_data_directory:
                    if os.path.exists(test_base + pdd + '/'):
                        pcap_file_path = std_glob.glob(test_base + pdd + '/*.pcap')[0]
                        parameter_setting['test_input_pcap'].append(pcap_file_path)
                parameter_setting_list.append(parameter_setting)
            else:
                for e in std_glob.glob(d + '/**/'):
                    if os.path.exists(e + 'timestamps/'):
                        ts_file_path = std_glob.glob(e + 'timestamps/*.timestamps')[0]
                        ts_file_name = ts_file_path.split('/')[-1]
                        device_ip = device_ip_map.get(ts_file_name, [])
                        parameter_setting = {
                            'train_tsfile': ts_file_path,
                            'device_ip': device_ip, # IoT device or local phone
                            'train_input_pcap': [],
                            'test_input_pcap': [],
                        }
                        for pdd in possible_data_directory:
                            if os.path.exists(e + pdd + '/'):
                                pcap_file_path = std_glob.glob(e + pdd + '/*.pcap')[0]
                                parameter_setting['train_input_pcap'].append(pcap_file_path)
                        test_base = e.replace('standalone', 'smarthome')
                        for pdd in possible_data_directory:
                            if os.path.exists(test_base + pdd + '/'):
                                pcap_file_path = std_glob.glob(test_base + pdd + '/*.pcap')[0]
                                parameter_setting['test_input_pcap'].append(pcap_file_path)
                        parameter_setting_list.append(parameter_setting)
    return parameter_setting_list


if __name__ == '__main__':
    p = './pingpong/Code/Projects/PacketLevelSignatureExtractor/execute_signature_generation.sh'
    device_ip_map = get_device_ip_map(p)
    print(device_ip_map)
    get_parameter_setting('./PingPongData/PingPong/PingPong/evaluation-datasets/', device_ip_map)