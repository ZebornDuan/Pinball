TRAIN_TEST_SETTING = [
    {
        'device-type': 'amazon-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.189',
        'timestamp': '/evaluation-datasets/local-phone/standalone/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/amazon-plug/wlan1/amazon-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/amazon-plug/wlan1/amazon-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'wemo-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/wemo-plug/timestamps/wemo-plug-nov-20-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/wemo-plug/wlan1/wemo-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/wemo-plug/wlan1/wemo-plug.wlan1.detection.pcap'
            ],
    },
    {
        'device-type': 'wemo-insight-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/wemo-insight-plug/timestamps/wemo-insight-plug-nov-21-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'tplink-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.159',
        'timestamp': '/evaluation-datasets/local-phone/standalone/tplink-plug/timestamps/tplink-plug-nov-8-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/tplink-plug/wlan1/tplink-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'dlink-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.199',
        'timestamp': '/evaluation-datasets/local-phone/standalone/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/dlink-plug/wlan1/dlink-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'dlink-plug',
        'H': 0.4, 'KL': 6, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/dlink-plug/timestamps/dlink-plug-nov-7-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/dlink-plug/wlan1/dlink-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/dlink-plug/wlan1/dlink-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'st-plug',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/st-plug/timestamps/st-plug-nov-12-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/st-plug/wlan1/st-plug.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/st-plug/wlan1/st-plug.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'sengled-bulb',
        'H': 0.45, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/sengled-bulb/sengled-bulb-onoff/timestamps/sengled-bulb-onoff-apr-24-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/sengled-bulb/sengled-bulb-onoff/wlan1/sengled-bulb-onoff.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'sengled-bulb',
        'H': 0.45, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/sengled-bulb/sengled-bulb-intensity/timestamps/sengled-bulb-intensity-apr-17-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/sengled-bulb/sengled-bulb-intensity/wlan1/sengled-bulb-intensity.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'tplink-bulb',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-apr-29-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.detection.pcap'
            ],
    },
    {
        'device-type': 'tplink-bulb',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-nov-16-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.detection.pcap'
            ],
    },
    {
        'device-type': 'tplink-bulb',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-apr-12-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.detection.pcap'
            ],
    },
    {
        'device-type': 'nest-thermostat',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/nest-thermostat/timestamps/nest-thermostat-nov-15-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/nest-thermostat/wlan1/nest-thermostat.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/nest-thermostat/wlan1/nest-thermostat.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'ecobee-thermostat',
        'H': 0.25, 'KL': 2, 'OD': 0.09,
        'ip': '192.168.1.130',
        'timestamp': '/evaluation-datasets/local-phone/standalone/ecobee-thermostat/ecobee-thermostat-hvac/timestamps/ecobee-thermostat-hvac-apr-17-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/ecobee-thermostat/ecobee-thermostat-hvac/wlan1/ecobee-thermostat-hvac.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'ecobee-thermostat',
        'H': 0.25, 'KL': 2, 'OD': 0.09,
        'ip': '192.168.1.130',
        'timestamp': '/evaluation-datasets/local-phone/standalone/ecobee-thermostat/ecobee-thermostat-fan/timestamps/ecobee-thermostat-fan-apr-18-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/ecobee-thermostat/ecobee-thermostat-fan/wlan1/ecobee-thermostat-fan.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'rachio-sprinkler',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.143',
        'timestamp': '/evaluation-datasets/local-phone/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-apr-18-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'rachio-sprinkler',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.143',
        'timestamp': '/evaluation-datasets/local-phone/standalone/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-apr-18-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'blossom-sprinkler',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.229',
        'timestamp': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-jan-14-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'blossom-sprinkler',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-quickrun/timestamps/blossom-sprinkler-quickrun-jan-14-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/blossom-sprinkler/blossom-sprinkler-quickrun/wlan1/blossom-sprinkler-quickrun.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'blossom-sprinkler',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-mode/timestamps/blossom-sprinkler-mode-apr-15-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/blossom-sprinkler/blossom-sprinkler-mode/wlan1/blossom-sprinkler-mode.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'ring-alarm',
        'H': 0.25, 'KL': 2, 'OD': 0.15,
        'ip': '192.168.1.113',
        'timestamp': '/evaluation-datasets/local-phone/standalone/ring-alarm/timestamps/ring-alarm-apr-26-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/ring-alarm/wlan1/ring-alarm.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/ring-alarm/wlan1/ring-alarm.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'arlo-camera',
        'H': 0.25, 'KL': 2, 'OD': 0.35,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/arlo-camera/timestamps/arlo-camera-nov-13-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/arlo-camera/wlan1/arlo-camera.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/arlo-camera/wlan1/arlo-camera.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'dlink-siren',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/dlink-siren/timestamps/dlink-siren-nov-9-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/dlink-siren/wlan1/dlink-siren.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/dlink-siren/wlan1/dlink-siren.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'kwikset-doorlock',
        'H': 0.4, 'KL': 6, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/kwikset-doorlock/timestamps/kwikset-doorlock-nov-10-2018.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/kwikset-doorlock/wlan1/kwikset-doorlock.wlan1.detection.pcap', 
            ],
    },
    {
        'device-type': 'roomba-vacuum-robot',
        'H': 0.25, 'KL': 2, 'OD': 0.2,
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/local-phone/standalone/roomba-vacuum-robot/timestamps/roomba-vacuum-robot-apr-25-2019.timestamps',
        'input-pcap': '/evaluation-datasets/local-phone/standalone/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.local.pcap',
        'test-pcap': [
                '/evaluation-datasets/local-phone/smarthome/roomba-vacuum-robot/wlan1/roomba-vacuum-robot.wlan1.detection.pcap', 
            ],
    },
]

SIGNATURE_EXTRACTION_SETTING = [
    # IFTTT
    {
        'device-type': 'arlo-camera',
        'ip': '192.168.1.146',
        'timestamp': '/evaluation-datasets/ifttt/standalone/arlo-camera/timestamps/arlo-camera-ifttt-dec-15-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/arlo-camera/wlan1/arlo-camera.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'dlink-plug',
        'ip': '192.168.1.199',
        'timestamp': '/evaluation-datasets/ifttt/standalone/dlink-plug/timestamps/dlink-plug-ifttt-dec-11-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/dlink-plug/wlan1/dlink-plug.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'dlink-siren',
        'ip': '192.168.1.184',
        'timestamp': '/evaluation-datasets/ifttt/standalone/dlink-siren/timestamps/dlink-siren-ifttt-dec-14-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/dlink-siren/wlan1/dlink-siren.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'hue-bulb',
        'ip': '192.168.1.101',
        'timestamp': '/evaluation-datasets/ifttt/standalone/hue-bulb/hue-bulb-onoff/timestamps/hue-bulb-onoff-ifttt-dec-15-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/hue-bulb/hue-bulb-onoff/eth1/hue-bulb-onoff.eth1.ifttt.pcap',
    },
    {
        'device-type': 'hue-bulb',
        'ip': '192.168.1.101',
        'timestamp': '/evaluation-datasets/ifttt/standalone/hue-bulb/hue-bulb-intensity/timestamps/hue-bulb-intensity-ifttt-dec-20-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/hue-bulb/hue-bulb-intensity/eth1/hue-bulb-intensity.eth1.ifttt.pcap',
    },
    {
        'device-type': 'rachio-sprinkler',
        'ip': '192.168.1.144',
        'timestamp': '/evaluation-datasets/ifttt/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-ifttt-dec-12-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'tplink-bulb',
        'ip': '192.168.1.140',
        'timestamp': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-onoff/timestamps/tplink-bulb-onoff-ifttt-dec-14-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-onoff/wlan1/tplink-bulb-onoff.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'tplink-bulb',
        'ip': '192.168.1.140',
        'timestamp': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-color/timestamps/tplink-bulb-color-ifttt-dec-18-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-color/wlan1/tplink-bulb-color.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'tplink-bulb',
        'ip': '192.168.1.140',
        'timestamp': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-intensity/timestamps/tplink-bulb-intensity-ifttt-dec-18-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/tplink-bulb/tplink-bulb-intensity/wlan1/tplink-bulb-intensity.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'tplink-plug',
        'ip': '192.168.1.159',
        'timestamp': '/evaluation-datasets/ifttt/standalone/tplink-plug/timestamps/tplink-plug-ifttt-dec-10-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/tplink-plug/wlan1/tplink-plug.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'wemo-insight-plug',
        'ip': '192.168.1.136',
        'timestamp': '/evaluation-datasets/ifttt/standalone/wemo-insight-plug/timestamps/wemo-insight-plug-ifttt-dec-14-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.ifttt.pcap',
    },
    {
        'device-type': 'wemo-plug',
        'ip': '192.168.1.146',
        'timestamp': '/evaluation-datasets/ifttt/standalone/wemo-plug/timestamps/wemo-plug-ifttt-dec-16-2019.timestamps',
        'input-pcap': '/evaluation-datasets/ifttt/standalone/wemo-plug/wlan1/wemo-plug.wlan1.ifttt.pcap',
    },
    # remote
    {
        'device-type': 'amazon-plug',
        'ip': '192.168.1.189',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/amazon-plug/timestamps/amazon-plug-dec-6-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/amazon-plug/wlan1/amazon-plug.wlan1.remote.pcap',
    },
    {
        'device-type': 'dlink-plug',
        'ip': '192.168.1.199',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/dlink-plug/timestamps/dlink-plug-dec-2-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/dlink-plug/wlan1/dlink-plug.wlan1.remote.pcap',
    },
    {
        'device-type': 'rachio-sprinkler',
        'ip': '192.168.1.143',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/timestamps/rachio-sprinkler-quickrun-dec-4-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/rachio-sprinkler/rachio-sprinkler-quickrun/wlan1/rachio-sprinkler-quickrun.wlan1.remote.pcap',
    },
    {
        'device-type': 'rachio-sprinkler',
        'ip': '192.168.1.143',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/rachio-sprinkler/rachio-sprinkler-mode/timestamps/rachio-sprinkler-mode-dec-4-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/rachio-sprinkler/rachio-sprinkler-mode/wlan1/rachio-sprinkler-mode.wlan1.remote.pcap',
    },
    {
        'device-type': 'ring-alarm',
        'ip': '192.168.1.113',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/ring-alarm/timestamps/ring-alarm-dec-9-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/ring-alarm/wlan1/ring-alarm.wlan1.remote.pcap',
    },
    {
        'device-type': 'tplink-plug',
        'ip': '192.168.1.159',
        'timestamp': '/evaluation-datasets/remote-phone/standalone/tplink-plug/timestamps/tplink-plug-dec-2-2019.timestamps',
        'input-pcap': '/evaluation-datasets/remote-phone/standalone/tplink-plug/wlan1/tplink-plug.wlan1.remote.pcap',
    },
    # public
    {
        'device-type': 'blink-camera',
        'ip': '192.168.1.228',
        'timestamp': '/evaluation-datasets/public-dataset/standalone/blink-camera/blink-camera-watch/timestamps/blink-camera-watch-retraining-dec-23-2019.timestamps',
        'input-pcap': '/evaluation-datasets/public-dataset/standalone/blink-camera/blink-camera-watch/wlan1/blink-camera-watch.wlan1.local.pcap',
    },
    {
        'device-type': 'blink-camera',
        'ip': '192.168.1.228',
        'timestamp': '/evaluation-datasets/public-dataset/standalone/blink-camera/blink-camera-photo/timestamps/blink-camera-photo-retraining-dec-24-2019.timestamps',
        'input-pcap': '/evaluation-datasets/public-dataset/standalone/blink-camera/blink-camera-photo/wlan1/blink-camera-photo.wlan1.local.pcap',
    },
    {
        'device-type': 'tplink-plug',
        'ip': '192.168.1.160',
        'timestamp': '/evaluation-datasets/public-dataset/standalone/tplink-plug/timestamps/tplink-plug-retraining-dec-25-2019.timestamps',
        'input-pcap': '/evaluation-datasets/public-dataset/standalone/tplink-plug/wlan1/tplink-plug.wlan1.local.pcap',
    },
    {
        'device-type': 'wemo-insight-plug',
        'ip': '192.168.1.246',
        'timestamp': '/evaluation-datasets/public-dataset/standalone/wemo-insight-plug/timestamps/wemo-insight-plug-retraining-jan-9-2020.timestamps',
        'input-pcap': '/evaluation-datasets/public-dataset/standalone/wemo-insight-plug/wlan1/wemo-insight-plug.wlan1.local.pcap',
    },
    # same-vendor
    {
        'device-type': 'tplink-two-outlet-plug',
        'ip': '192.168.1.178',
        'timestamp': '/evaluation-datasets/same-vendor/standalone/tplink-two-outlet-plug/timestamps/tplink-two-outlet-plug-dec-22-2019.timestamps',
        'input-pcap': '/evaluation-datasets/same-vendor/standalone/tplink-two-outlet-plug/wlan1/tplink-two-outlet-plug.wlan1.local.pcap',
    },
    {
        'device-type': 'tplink-power-strip',
        'ip': '192.168.1.142',
        'timestamp': '/evaluation-datasets/same-vendor/standalone/tplink-power-strip/timestamps/tplink-power-strip-dec-22-2019.timestamps',
        'input-pcap': '/evaluation-datasets/same-vendor/standalone/tplink-power-strip/wlan1/tplink-power-strip.wlan1.local.pcap',
    },
    {
        'device-type': 'tplink-bulb-white',
        'ip': '192.168.1.227',
        'timestamp': '/evaluation-datasets/same-vendor/standalone/tplink-bulb-white/tplink-bulb-white-onoff/timestamps/tplink-bulb-white-onoff-dec-21-2019.timestamps',
        'input-pcap': '/evaluation-datasets/same-vendor/standalone/tplink-bulb-white/tplink-bulb-white-onoff/wlan1/tplink-bulb-white-onoff.wlan1.local.pcap',
    },
    {
        'device-type': 'tplink-bulb-white',
        'ip': '192.168.1.227',
        'timestamp': '/evaluation-datasets/same-vendor/standalone/tplink-bulb-white/tplink-bulb-white-intensity/timestamps/tplink-bulb-white-intensity-dec-21-2019.timestamps',
        'input-pcap': '/evaluation-datasets/same-vendor/standalone/tplink-bulb-white/tplink-bulb-white-intensity/wlan1/tplink-bulb-white-intensity.wlan1.local.pcap',
    },
    {
        'device-type': 'tplink-camera',
        'ip': '192.168.1.235',
        'timestamp': '/evaluation-datasets/same-vendor/standalone/tplink-camera/tplink-camera-onoff/wlan1/tplink-camera-onoff.wlan1.local.pcap',
        'input-pcap': '/evaluation-datasets/same-vendor/standalone/tplink-camera/tplink-camera-onoff/timestamps/tplink-camera-onoff-dec-22-2019.timestamps',
    },
]