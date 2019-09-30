import os
import csv
import sys
import time
import yaml
import argparse
from scapy.all import sniff, PcapWriter


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default='eth0', help='interface')
args = parser.parse_args()

ips = os.popen(
    "ip a | grep inet | awk '{print $2}' | cut -d '/' -f 1").read().split('\n')
ips.pop()

workDir = os.path.dirname(os.path.abspath(__file__)) + '/'
additoinsDir = workDir + 'additions/'


def process_sniffed_packet(p):
    # print(p.summary())
    # print(p.show())
    srcIP = p.sprintf('%IP.src%')
    sport = p.sprintf('%sport%')
    dstIP = p.sprintf('%IP.dst%')
    dport = p.sprintf('%dport%')
    # print(srcIP, sport, dstIP, dport)

    netstatCmd = 'netstat -tunpe4'
    if srcIP in ips:
        ip = srcIP
        port = sport
    elif dstIP in ips:
        ip = dstIP
        port = dport
        netstatCmd += 'l'
    else:
        return
    netstatCmd += " | egrep '0.0.0.0:" + port + '|' + ip + \
        ':' + port + "' | awk '{for (i=7; i<=NF; i++) print $i}'"

    netstatResult = os.popen(netstatCmd).read()
    if netstatResult:
        uid = netstatResult.split()[0]
        pid = netstatResult.split()[2].split('/')[0]

        pInfo = { 'uid': int(uid) }

        with open(additoinsDir + str(p.time).split('.')[0] + '-' + sport + '-' + dport + '.yml', 'w') as yamlFile:
            if pid != '-':
                pInfo['pid'] = int(pid)
                pInfo['cmd'] = os.popen('ps -o cmd= -p ' + pid).read().split('\n')[0]
                pInfo['comm'] = os.popen('ps -o comm= -p ' + pid).read().split('\n')[0]
            yaml.dump(pInfo, yamlFile)

    pDump.write(p)

if os.system('ip > /dev/null 2>&1') == 32512:
    print('ip Not Found. Please install iproute2!')
    exit()
if os.system('ip a s ' + args.interface + ' > /dev/null 2>&1') == 256:
    print('iface ' + args.interface +' Not Found. Please check the arguments!')
    exit()
if os.system('netstat > /dev/null 2>&1') == 32512:
    print('netstat Not Found. Please install net-tools!')
    exit()

pDump = PcapWriter(workDir + 'package.pcap', append=True, sync=True)
sniff(iface=args.interface, prn=process_sniffed_packet)
