import io
import os
import csv
import sys
import time
import zipfile
import argparse
import requests
from scapy.all import sniff, wrpcap


parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', default='eth0', help='interface')
parser.add_argument('-c', '--count', default='10', help='count')
args = parser.parse_args()

workDir = os.path.dirname(os.path.abspath(__file__)) + '/'
pkgDir = workDir + 'package/'
pkgOutDir = workDir + 'package_out/'
pkgForTrainingDir = workDir + 'package_for_training/'


def download_cfm():
    print('CICFlowmeter Not Found. Downloading...')
    r = requests.get(
        'https://www.unb.ca/cic/_assets/documents/cicflowmeter-4.zip')
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall(path=workDir)
    os.system('chmod +x ' + workDir + 'CICFlowMeter-4.0/bin/cfm')
    print('Download Complete!')


if not os.path.isdir(workDir + 'CICFlowMeter-4.0'):
    download_cfm()
if os.system('netstat > /dev/null 2>&1') == 32512:
    print('netstat Not Found. Please install net-tools!')
    exit()

while True:
    t = str(time.time())
    pkgName = t + '.pcap'
    pkgPath = pkgDir + pkgName
    pkgOutPath = pkgOutDir + t + '.pcap_Flow.csv'
    pkgForTrainingPath = pkgForTrainingDir + t + '.csv'
    wrpcap(pkgPath, sniff(iface=args.interface, count=int(args.count)))
    os.chdir(workDir + 'CICFlowMeter-4.0/bin')
    os.system('./cfm ' + workDir + 'package ' + workDir + 'package_out')
    os.remove(pkgPath)
    with open(pkgOutPath) as csvFile:
        rows = csv.reader(csvFile)
        with open(pkgForTrainingPath, 'w') as newCsvFile:
            writer = csv.writer(newCsvFile)
            for index, row in enumerate(rows):
                if index:
                    srcIP = row[1]
                    srcPort = row[2]
                    dstIP = row[3]
                    dstPort = row[4]

                    ips = os.popen("ip a | grep inet | awk '{print $2}' | cut -d '/' -f 1").read().split('\n')
                    ips.pop()

                    if dstIP in ips:
                        ip = dstIP
                        port = dstPort

                        pid = os.popen("netstat -tunlp4 | grep -E '0.0.0.0:" + port + '|' + ip + ':' + port + "' | awk '{print $7}'").read().split('/')[0]
                        uid = os.popen('stat -c "%u" /proc/' + pid).read().split('\n')[0] if pid else ''
                    # else:

                    row.extend([pid, uid])
                else:
                    row.extend(['pid', 'uid'])

                writer.writerow(row)
    os.remove(pkgOutPath)
