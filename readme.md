# Pinball: General and Robust Signature Extraction for Smart Home IoT Devices
## Setup
### Dataset Acquirement
./pingpong/   [UCI PingPong Dataset--http://plrg.ics.uci.edu/pingpong/](http://plrg.ics.uci.edu/pingpong/)

./MonIoTr/    [MonIoTr Dataset--https://github.com/NEU-SNS/intl-iot](https://github.com/NEU-SNS/intl-iot)

### Running Requirements
```
Python >= 3.6
arrow >= 0.15 (pip install arrow)
```

### Usage
```
usage: pinball.py [-h] [-r R] [-e] [-d] [-s] [--s1 S1] [--s2 S2] [--tz TZ]
                  [--ip IP] [--ts TS] [--H H] [--KL KL] [--OD OD]

optional arguments:
  -h, --help  show this help message and exit
  -r R        input pcap file path
  -e          perform signature extraction
  -d          perform event decetion
  -s          store the extracted signatures in pickle format
  --s1 S1     signature(ON) file path (serialization of SignaturePinball
              object in pickle format)
  --s2 S2     signature(OFF) file path (serialization of SignaturePinball
              object in pickle format)
  --tz TZ     local timezone, default: Asia/Shanghai
  --ip IP     IP address of the target device
  --ts TS     timestamp file for triggered events (PingPong format)
  --H H       threshold of Hellinger distance metric, default value: 0.25
  --KL KL     threshold of KL divergence metric, default value: 2
  --OD OD     threshold of occurrence discrepancy metric, default: 0.15

example: python pinball.py -e -s -r ./pingpong/evaluation-datasets/local-phone/standalone/amazon-plug/wlan1/amazon-plug.wlan1.local.pcap --ts ./pingpong/evaluation-datasets/local-phone/standalone/amazon-plug/timestamps/amazon-plug-apr-16-2019.timestamps --tz Asia/Shanghai --ip 192.168.1.189
```

## Results on PingPong Dataset
format: 
device-name signature-type Match-Pinball/Match-PingPong(per 100 events) FP-Pinball/FP-PingPong

#### amazon-plug Device-Cloud 100/99 0/0
- ON-Pinball

| 443↓ | 146↓ | 392↓ | 107↑ | 60↓ | 1514↓ | 54↑ | 90↑ | 103↑ | 143↓ | 445↓ | 235↓ | 107↓ | 267↑ | 316↑ | 87↓ | 1514↑ | 129↑ | 123↓ | 62↓ | 63↓ | 62↑ | 416↓ | 1210↓ | 239↑ | 1099↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01164 | 0.02398 | 0.02351 | 0.02707 | 0.02351 | 0.04726 | 0.24982 | 0.01164 | 0.01259 | 0.0114 | 0.01187 | 0.02351 | 0.02351 | 0.02826 | 0.01401 | 0.01211 | 0.01187 | 0.05771 | 0.02493 | 0.02802 | 0.04702 | 0.02802 | 0.01164 | 0.02351 | 0.0266 | 0.01377 | 0.17122 |
- ON-PingPong
[443↓ - 445↓] & 1099↑ 235↓

- OFF-Pinball

| 146↓ | 392↓ | 317↑ | 107↑ | 444↓ | 60↓ | 1514↓ | 54↑ | 90↑ | 103↑ | 143↓ | 235↓ | 107↓ | 267↑ | 87↓ | 1514↑ | 129↑ | 123↓ | 1179↑ | 446↓ | 62↓ | 63↓ | 62↑ | 1210↓ | 239↑ | 417↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.02355 | 0.02355 | 0.01437 | 0.02732 | 0.01154 | 0.02355 | 0.0471 | 0.24776 | 0.01201 | 0.01413 | 0.01107 | 0.02355 | 0.02355 | 0.02732 | 0.01178 | 0.01178 | 0.05747 | 0.02496 | 0.0139 | 0.01178 | 0.02638 | 0.0471 | 0.02638 | 0.02355 | 0.02779 | 0.01154 | 0.17522 |
- OFF-PingPong
[444↓ - 446↓] & 1079↑ 235↓ & 1514↑ 103↓ 235↑

#### wemo-plug Phone-Device 100/100 0/0
- ON/OFF-Pinball

| 475↑ | 259↑ | 66↓ | 430↓ | 74↑ | 54↑ | 54↓ | 246↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.07728 | 0.07728 | 0.11051 | 0.07728 | 0.08578 | 0.24961 | 0.24498 | 0.07728 |
- ON-PingPong
259↓ 475↓ 246↑

#### wemo-insight-plug Phone-Device 100/99 1/0
- ON/OFF-Pinball

| 475↑ | 259↑ | 66↓ | 464↓ | 74↑ | 54↑ | 54↓ | 246↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.07886 | 0.07886 | 0.10962 | 0.07886 | 0.08912 | 0.24132 | 0.24448 | 0.07886 |

- ON/OFF-PingPong
259↓ 475↓ 246↑

#### tplink-plug Device-Cloud & Phone-Cloud 100/100 0/0
- ON-Pinball

| 556↑ | 1514↓ | 583↑ | 117↓ | 257↑ | 66↑ | 79↑ | 97↑ | 66↓ | 921↓ | 112↓ | 74↑ | 74↓ | 115↑ | 641↑ | 1293↓ | 237↓\~240↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01698 | 0.05093 | 0.01698 | 0.01698 | 0.01698 | 0.27708 | 0.01698 | 0.01698 | 0.23463 | 0.01732 | 0.03396 | 0.05739 | 0.05705 | 0.03463 | 0.10119 | 0.01698 | 0.01698 |

- ON-PingPong
112↓ 115↑ & 556↑ 1293↓

- OFF-Pinball

| 557↑ | 1514↓ | 583↑ | 117↓ | 66↑ | 79↑ | 97↑ | 66↓ | 921↓ | 112↓ | 1294↓ | 74↑ | 74↓ | 115↑ | 257↑ | 641↑ | 238↓\~240↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01711 | 0.05132 | 0.01711 | 0.01711 | 0.28156 | 0.01711 | 0.01711 | 0.23982 | 0.01745 | 0.03421 | 0.01676 | 0.05816 | 0.05816 | 0.03421 | 0.01745 | 0.08827 | 0.01711 |

- OFF-PingPong
112↓ 115↑ & 557↑ [1294↓\~1295↓]

#### dlink-plug Device-Cloud 100/95 0/0
- ON/OFF-Pinball

| 91↓ | 288↑ | 647↓ | 103↓ | 66↑ | 1227↓ | 66↓ | 784↑ | 1052↑ | 74↑ | 74↓ | 54↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.03346 | 0.03098 | 0.0316 | 0.0316 | 0.13197 | 0.03222 | 0.12392 | 0.03098 | 0.03036 | 0.04957 | 0.03098 | 0.2627 | 0.17968 |

- ON/OFF-PingPong
91↓ 1227↓ 784↑ & 1052↑ 647↓

#### dlink-plug Phone-Cloud 100/98 0/0
- ON-Pinball

| 66↑ | 97↑ | 66↓ | 74↑ | 613↓ | 74↓ | 54↑ | 292↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.30881 | 0.05803 | 0.15648 | 0.06321 | 0.05285 | 0.06114 | 0.12642 | 0.05596 | 0.1171 |

- ON-PingPong
[1109↑\~1123↑] 613↓

- OFF-Pinball

| 66↑ | 97↑ | 66↓ | 74↑ | 613↓ | 74↓ | 54↑ | 292↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.33731 | 0.05423 | 0.14751 | 0.06725 | 0.05531 | 0.06725 | 0.10521 | 0.05531 | 0.11063 |

- OFF-PingPong
[1110↑\~1124↑] 613↓

#### st-plug Phone-Cloud 100/92 0/0
- ON-Pinball

| 777↓ | 699↑ | 136↑ | 66↑ | 66↓ | 74↑ | 279↑ | 74↓ | 511↓ | 612↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.05762 | 0.05273 | 0.10449 | 0.30957 | 0.22949 | 0.0498 | 0.04883 | 0.0498 | 0.04883 | 0.04883 |

- ON-PingPong
699↑ 511↓ & 777↓ 136↑

- OFF-Pinball

| 780↓ | 136↑ | 616↓ | 66↑ | 66↓ | 700↑ | 74↑ | 279↑ | 74↓ | 511↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.05388 | 0.09735 | 0.04726 | 0.31853 | 0.23251 | 0.04915 | 0.05293 | 0.04726 | 0.05293 | 0.0482 |

- OFF-PingPong
700↑ 511↓ & 780↓ 136↑

#### sengled-bulb-onoff Phone-Cloud 99/97 0/0
- ON-Pinball

| 1063↓ | 66↑ | 1277↓ | 66↓ | 54↑ | 211↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.07891 | 0.32138 | 0.08178 | 0.14491 | 0.14347 | 0.08321 | 0.14634 |

- ON-PingPong
211↑ 1063↓ & 1277↓

- OFF-Pinball

| 1063↓ | 66↑ | 66↓ | 1276↓ | 54↑ | 211↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.03204 | 0.71463 | 0.05985 | 0.03869 | 0.05985 | 0.03083 | 0.06409 |

- OFF-PingPong
211↑ 1063↓ 1276↓

#### sengled-bulb-intensity Phone-Cloud 100/99 0/0
- Odd-Pinball

| 1275↓ | 66↓ | 66↑ | 215↑ |
| ---- | ---- | ---- | ---- |
| 0.25753 | 0.2408 | 0.3311 | 0.17057 |

- Even-Pinball

| 66↓ | 66↑ | 217↑ | 1277↓ |
| ---- | ---- | ---- | ---- |
| 0.19466 | 0.29008 | 0.19466 | 0.32061 |

- PingPong
[1275↓\~1277↓] [215↑\~217↑]

#### tplink-bulb-intensity Phone-Device 100/100 0/0
- Odd-Pinball

| 58↓ | 240↑ | 74↑ | 54↑ | 287↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0.06215 | 0.06215 | 0.06961 | 0.30827 | 0.06215 | 0.43567 |

- Even-Pinball

| 58↓ | 289↓ | 74↑ | 54↑ | 54↓ | 242↑ |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0.06234 | 0.06234 | 0.06421 | 0.31047 | 0.43828 | 0.06234 |

- PingPong
[240↓\~242↓] [287↑\~289↑]

#### tplink-bulb-onoff Phone-Device 100/100 0/4
- ON-Pinball

| 309↓ | 71↑ | 227↓ | 58↓ | 198↑ | 520↑ | 66↑ | 66↓ | 1049↓ | 46↑ | 1454↓ | 74↑ | 54↑ | 627↑ | 1311↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.02292 | 0.0926 | 0.03159 | 0.03716 | 0.03097 | 0.02106 | 0.06782 | 0.0446 | 0.0799 | 0.0607 | 0.01827 | 0.03778 | 0.15918 | 0.04305 | 0.02137 | 0.23103 |

- ON-PingPong
198↓ 227↑

- OFF-Pinball

| 309↓ | 71↑ | 520↑ | 58↓ | 198↑ | 66↑ | 244↓ | 1473↓ | 66↓ | 46↑ | 74↑ | 1066↓ | 54↑ | 627↑ | 1311↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.02249 | 0.09249 | 0.02091 | 0.03674 | 0.03168 | 0.06747 | 0.03168 | 0.01837 | 0.03928 | 0.06272 | 0.03769 | 0.08172 | 0.1606 | 0.04054 | 0.02091 | 0.23472 |

- OFF-PingPong
198↓ 244↑

#### tplink-bulb-color Phone-Device 100/100 0/0
- Pinball

| 58↓ | 317↑ | 74↑ | 54↑ | 287↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0.06273 | 0.0615 | 0.06642 | 0.30935 | 0.0615 | 0.4385 |

- PingPong
317↑ 287↓

#### nest-thermostat Phone-Cloud 95/93 0/1
- FAN-ON-Pinball

| 74↓ | 66↓ | 66↑ | 74↑ | 830↓\~834↓ | 891↑\~894↑ |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0.05498 | 0.32261 | 0.46369 | 0.05498 | 0.05187 | 0.05187 |

- FAN-ON-PingPong
[891↑\~894↑] [830↓\~834↓]

- FAN-OFF-Pinball

| 74↓ | 66↓ | 66↑ | 74↑ | 829↓\~834↓ | 858↑\~860↑ |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 0.05516 | 0.31673 | 0.48043 | 0.05961 | 0.04359 | 0.04448 |

- FAN-OFF-PingPong
[858↑\~860↑] [829↓\~834↓]


#### ecobee-thermostat-hvac Phone-Cloud 95/99 0/0
- Auto-Pinball

| 583↑ | 1232↓ | 74↑ | 1514↓ | 97↑ | 192↑ | 926↓ | 1484↓ | 66↓ | 97↓ | 640↓ | 231↓ | 149↓ | 1300↑ | 66↑ | 112↑ | 243↑ | 340↓ | 499↓ | 74↓ | 144↓\~148↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.00849 | 0.00802 | 0.00833 | 0.01501 | 0.00794 | 0.00794 | 0.00424 | 0.43519 | 0.08207 | 0.00778 | 0.00417 | 0.00778 | 0.02272 | 0.00464 | 0.31759 | 0.00825 | 0.02295 | 0.00731 | 0.00731 | 0.00865 | 0.00362 |

- Auto-PingPong
1300↑ 640↓

- OFF-Pinball

| 583↑ | 1232↓ | 74↑ | 1514↓ | 97↑ | 192↑ | 926↓ | 1484↓ | 66↓ | 97↓ | 640↓ | 231↓ | 149↓ | 66↑ | 112↑ | 243↑ | 340↓ | 499↓ | 74↓ | 1299↑ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.00837 | 0.00775 | 0.00806 | 0.01432 | 0.00798 | 0.00744 | 0.00407 | 0.4271 | 0.08077 | 0.00798 | 0.00446 | 0.0079 | 0.02215 | 0.33451 | 0.0083 | 0.02215 | 0.00728 | 0.00697 | 0.00798 | 0.00446 |

- OFF-PingPong
1299↑ 640↓

#### ecobee-thermostat-fan Phone-Cloud 95/100 0/0
- ON-Pinball

| 583↑ | 1387↑ | 1422↓ | 74↑ | 1514↓ | 97↑ | 192↑ | 926↓ | 1484↓ | 66↓ | 97↓ | 640↓ | 231↓ | 149↓ | 66↑ | 112↑ | 243↑ | 340↓ | 499↓ | 74↓ | 139↓\~148↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01342 | 0.00677 | 0.04727 | 0.01584 | 0.02236 | 0.01431 | 0.01239 | 0.00639 | 0.30114 | 0.08816 | 0.01265 | 0.00639 | 0.01265 | 0.03335 | 0.32222 | 0.00779 | 0.03271 | 0.01112 | 0.01086 | 0.01546 | 0.00677 |

- ON-PingPong
1387↑ 640↓

- Auto-Pinball

| 583↑ | 1232↓ | 74↑ | 1514↓ | 97↑ | 192↑ | 926↓ | 1484↓ | 66↓ | 97↓ | 1389↑ | 640↓ | 231↓ | 149↓ | 66↑ | 112↑ | 243↑ | 340↓ | 499↓ | 74↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01485 | 0.00735 | 0.01557 | 0.02451 | 0.01514 | 0.01211 | 0.00721 | 0.33415 | 0.09615 | 0.01456 | 0.00764 | 0.00721 | 0.01442 | 0.03748 | 0.3082 | 0.00735 | 0.03633 | 0.01254 | 0.01182 | 0.01542 |

- Auto-PingPong
1389↑ 640↓

#### rachio-sprinkler-quickrun Device Cloud 100/100 0/0
- QuickRun-Pinball

| 267↓ | 54↑ | 155↑ | 54↓ |
| ---- | ---- | ---- | ---- |
| 0.16781 | 0.16781 | 0.16781 | 0.49658 |

- QuickRun-PingPong
267↓ 155↑

- Stop-Pinball

| 219↓ | 155↑ | 235↓ | 496↑ | 171↑ | 395↑ | 54↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.08237 | 0.08402 | 0.08237 | 0.08237 | 0.08237 | 0.08237 | 0.08402 | 0.4201 |

- Stop-PingPong
496↑ 155↑ 395↑

#### rachio-sprinkler-mode Device-Cloud 100/100 0/0
- Pinball

| 299↓ | 395↑ | 155↑ | 54↓ |
| ---- | ---- | ---- | ---- |
| 0.20319 | 0.1992 | 0.1992 | 0.39841 |

- PingPong
299↓ 155↑ 395↑

#### blossom-sprinkler-quickrun Device-Cloud 96/96 0/0
- QuickRun-Pinball

| 58↑ | 58↓ | 326↓ | 177↑ | 78↑ | 505↓ | 311↓ | 69↑ | 54↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.09398 | 0.09398 | 0.04605 | 0.04605 | 0.04605 | 0.04605 | 0.04605 | 0.04793 | 0.29135 | 0.24248 |

- QuickRun-PingPong
326↓ & 177↑ 505↓

- Stop-Pinball

| 58↑ | 296↑ | 58↓ | 326↓ | 177↑ | 78↑ | 238↑ | 311↓ | 458↓ | 56↑ | 69↑ | 54↑ | 54↓ | 388↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.09158 | 0.02991 | 0.09096 | 0.02991 | 0.03053 | 0.02991 | 0.0293 | 0.0293 | 0.02991 | 0.0293 | 0.02991 | 0.27778 | 0.24237 | 0.0293 |

- Stop-PingPong
326↓ & 177↑ 458↓ & 238↑ 56↑ 388↓

#### blossom-sprinkler-quickrun Phone-Cloud 93/93 0/0
- QuickRun-Pinball

| 649↑ | 583↑ | 104↑ | 459↓ | 74↑ | 54↑ | 116↑ | 66↓ | 112↓ | 119↑ | 507↓ | 425↓ | 66↑ | 112↑ | 139↓ | 226↓ | 574↑ | 108↑ | 135↓ | 282↑ | 550↓ | 567↑ | 74↓ | 54↓ | 560↑\~562↑ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.0233 | 0.02144 | 0.0247 | 0.02283 | 0.02749 | 0.06757 | 0.02237 | 0.16076 | 0.0233 | 0.02982 | 0.02377 | 0.0247 | 0.17381 | 0.02516 | 0.02283 | 0.02097 | 0.04753 | 0.02237 | 0.02423 | 0.02097 | 0.0247 | 0.02283 | 0.02749 | 0.07269 | 0.02237 |

- QuickRun-PingPong
649↑ 459↓ 574↑ 507↓ & [135↓\~139↓]

- Stop-Pinball

| 574↑ | 617↑ | 431↓ | 550↓ | 66↑ | 348↓ | 66↓ | 567↑ | 54↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.0768 | 0.045 | 0.03957 | 0.07758 | 0.13654 | 0.08146 | 0.13344 | 0.07991 | 0.16912 | 0.16059 |

- Stop-PingPong
617↑ 431↓

#### blossom-sprinkler-mode Phone-Cloud 95/93 0/0
- Hibernate-Pinball

| 621↑ | 66↑ | 139↓ | 66↓ | 112↑ | 112↓ | 493↓ | 373↑\~374↑ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.07143 | 0.17638 | 0.06997 | 0.28863 | 0.1516 | 0.1035 | 0.06997 | 0.06851 |

- Hibernate-PingPong
621↑ 493↓

- Active-Pinball

| 622↑ | 1514↓ | 566↑ | 582↑ | 107↓ | 66↓ | 112↓ | 599↓ | 598↑ | 1398↓ | 66↑ | 112↑ | 139↓ | 144↓ | 554↓ | 478↓ | 494↓ | 577↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01743 | 0.10844 | 0.03626 | 0.01743 | 0.01743 | 0.18131 | 0.04498 | 0.01848 | 0.01743 | 0.02092 | 0.27022 | 0.0537 | 0.03487 | 0.01569 | 0.01743 | 0.03556 | 0.01918 | 0.03487 | 0.03835 |

- Active-PingPong
622↑ 494↓ & 599↓ 566↑ 554↓ 566↑

#### ring-alarm Device-Cloud 96/95 0/0
- Arm-Pinball

| 123↑ | 254↓ | 99↓ | 99↑ | 241↑ | 66↑ | 66↓ | 1514↑ | 181↓\~183↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.01749 | 0.02966 | 0.04525 | 0.20722 | 0.14335 | 0.05171 | 0.44829 | 0.03802 | 0.01901 |

- Arm-PingPong
99↓ 254↓ 99↑ & [181↓\~183↓] 99↑

- Disarm-Pinball

| 99↓ | 99↑ | 66↑ | 66↓ | 1514↑ | 255↓ | 181↓\~183↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.11404 | 0.12865 | 0.15205 | 0.38012 | 0.09747 | 0.07895 | 0.04873 |

- Disarm-PingPong
99↓ 255↓ 99↑ & [181↓\~183↓] 99↑

#### arlo-camera Phone-Cloud 99/98 0/3
- StreamOn-Pinball

| 320↓ | 74↑ | 1514↓ | 321↓ | 54↑ | 97↑ | 192↑ | 1613↑ | 117↓ | 66↓ | 97↓ | 113↓ | 66↑ | 1266↓ | 329↓ | 340↓ | 249↑ | 74↓ | 801↓ | 54↓ | 271↑\~273↑ | 310↑\~312↑ | 322↓\~324↓ | 1198↓\~1199↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.00276 | 0.00832 | 0.3985 | 0.00314 | 0.0167 | 0.00557 | 0.00783 | 0.00248 | 0.00529 | 0.02243 | 0.00513 | 0.00463 | 0.47445 | 0.00507 | 0.00265 | 0.00281 | 0.00463 | 0.00821 | 0.00281 | 0.00579 | 0.00276 | 0.00276 | 0.00281 | 0.00248 |

- StreamOn-PingPong
[338↑\~339↑] [326↓\~329↓] [364↑\~365↑] [1061↓\~1070↓] & [271↑\~273↑] [499↓\~505↓]

- StreamOff-Pinball

| 146↓ | 392↓ | 74↑ | 60↓ | 1514↓ | 54↑ | 97↑ | 254↑ | 352↓ | 1141↓ | 66↓ | 394↓ | 97↓ | 1199↓ | 66↑ | 1486↓ | 63↓ | 99↓ | 442↓ | 180↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.00212 | 0.00216 | 0.00494 | 0.00212 | 0.33339 | 0.07935 | 0.00437 | 0.00212 | 0.00216 | 0.00216 | 0.01303 | 0.00216 | 0.00424 | 0.00879 | 0.34092 | 0.17771 | 0.00416 | 0.00242 | 0.00212 | 0.00225 | 0.00727 |

- StreamOff-PingPong
[445↑\~449↑] 442↓

#### dlink-siren Phone-Cloud 100/98 0/0
- ON-Pinball

| 593↓ | 1076↑ | 66↑ | 66↓ | 74↑ | 74↓ | 54↑ | 292↑ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.04252 | 0.04252 | 0.5068 | 0.10204 | 0.04932 | 0.04592 | 0.08163 | 0.04507 | 0.08418 |

- ON-PingPong
1076↑ 593↓

- OFF-Pinball

| 66↑ | 66↓ | 74↑ | 613↓ | 74↓ | 54↑ | 292↑ | 54↓ | 1023↑ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.41362 | 0.11945 | 0.05726 | 0.05331 | 0.05429 | 0.09576 | 0.05133 | 0.10168 | 0.05331 |

- OFF-PingPong
1023↑ 613↓

#### kwikset-doorlock Phone-Cloud 100/100 1/0
- Lock-Pinball

| 639↓ | 699↑ | 136↑ | 66↑ | 66↓ | 74↑ | 279↑ | 74↓ | 54↑ | 511↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.04522 | 0.04696 | 0.04348 | 0.28261 | 0.17913 | 0.05391 | 0.04261 | 0.04783 | 0.10957 | 0.04783 | 0.10087 |

- Lock-PingPong
699↑ 511↓ & 639↓ 136↑

- Unlock-Pinball

| 647↓ | 136↑ | 66↑ | 66↓ | 701↑ | 74↑ | 279↑ | 74↓ | 54↑ | 511↓ | 54↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.045 | 0.045 | 0.30333 | 0.18812 | 0.0468 | 0.0495 | 0.0459 | 0.0495 | 0.09001 | 0.0459 | 0.09091 |

- Unlock-PingPong
701↑ 511↓ & 647↓ 136↑

#### roomba-vacuum-robot Phone-Cloud 97/94 0/0
- Clean-Pinball

| 105↑ | 559↓ | 66↑ | 107↓ | 66↓ | 78↑ | 171↑ | 432↓ | 825↓ | 261↓ | 54↑ | 54↓ | 1014↓\~1015↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.06321 | 0.06195 | 0.03635 | 0.1713 | 0.07554 | 0.06448 | 0.03603 | 0.0158 | 0.01549 | 0.04867 | 0.35335 | 0.04235 | 0.01549 |

- Clean-PingPong
[1014↓\~1015↓] 105↑ 432↓ 105↑

- Back-to-Station-Pinball

| 105↑ | 559↓ | 463↓ | 107↓ | 66↓ | 78↑ | 171↑ | 261↓ | 54↑ | 440↓ | 54↓ | 825↓\~826↓ |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
| 0.05488 | 0.03383 | 0.03314 | 0.16017 | 0.06835 | 0.07076 | 0.07042 | 0.05247 | 0.33483 | 0.01726 | 0.08664 | 0.01726 |

-Back-to-Station-PingPong
440↓ 105↑ [1018↓\~1024↓] 105↑
