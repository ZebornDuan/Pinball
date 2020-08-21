# __author__ = ZebornDuan

import datetime

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

if __name__ == '__main__':
    p = './pingpong/Code/Projects/PacketLevelSignatureExtractor/execute_signature_generation.sh'
    get_device_ip_map(p)