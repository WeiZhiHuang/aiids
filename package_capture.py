import io
import os
import csv
import sys
import time
import yaml
import zipfile
import argparse
import requests
from scapy.all import sniff, wrpcap, PcapWriter


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default='eth0', help='interface')
args = parser.parse_args()

ips = os.popen(
    "ip a | grep inet | awk '{print $2}' | cut -d '/' -f 1").read().split('\n')
ips.pop()

workDir = os.path.dirname(os.path.abspath(__file__)) + '/'
additoinsDir = workDir + 'additions/'


def download_cfm():
    print('CICFlowmeter Not Found. Downloading...')
    r = requests.get(
        'https://www.unb.ca/cic/_assets/documents/cicflowmeter-4.zip')
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall(path=workDir)
    os.system('chmod +x ' + workDir + 'CICFlowMeter-4.0/bin/cfm')
    print('Download Complete!')


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

        with open(additoinsDir + str(p.time) + '.yml', 'w') as yamlFile:
            if pid != '-':
                pInfo['pid'] = int(pid)
                pInfo['comm'] = os.popen('ps -o comm= -p ' + pid).read().split('\n')[0]
            yaml.dump(pInfo, yamlFile)

    pDump.write(p)


if not os.path.isdir(workDir + 'CICFlowMeter-4.0'):
    download_cfm()
if os.system('netstat > /dev/null 2>&1') == 32512:
    print('netstat Not Found. Please install net-tools!')
    exit()

pDump = PcapWriter(workDir + 'package.pcap', append=True, sync=True)
sniff(iface=args.interface, prn=process_sniffed_packet)
