import os
import yaml
import argparse
import threading
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
    pDump.write(p)
    if p.sprintf('%proto%') not in ['6', '17']:
        return

    # print(p.summary())
    # print(p.show())
    srcIP = p.sprintf('%IP.src%')
    sport = p.sprintf('%sport%')
    dstIP = p.sprintf('%IP.dst%')
    dport = p.sprintf('%dport%')
    # print(srcIP, sport, dstIP, dport)

    netstatCmd = 'netstat -tunpe4'
    if srcIP in ips:
        netstatCmd += " | egrep '" + srcIP + ':' + \
            sport + '.*' + dstIP + ':' + dport + "'"
    elif dstIP in ips:
        netstatCmd += 'l | grep :' + dport
    else:
        return

    netstatCmd += """ | cut -d'/' -f1 | awk '{printf $7" "$9" "; if ($9 != "-") system("ps o comm= o cmd= p"$9)}'"""
    # print(netstatCmd)

    netstatResult = os.popen(netstatCmd).read().split()
    # print(netstatResult)

    if netstatResult not in ([], ['0', '-']):
        with open(additoinsDir + str(p.time).split('.')[0] + '-' + sport + '-' + dport + '.yml', 'w') as yamlFile:
            pInfo = {'uid': int(netstatResult[0])}
            if len(netstatResult) > 2:
                pInfo.update({'pid': int(netstatResult[1]),
                              'comm': netstatResult[2], 'cmd': ' '.join(netstatResult[3:])})
            yaml.dump(pInfo, yamlFile)


if os.system('ip > /dev/null 2>&1') == 32512:
    print('ip Not Found. Please install iproute2!')
    exit()
if os.system('ip a s ' + args.interface + ' > /dev/null 2>&1') == 256:
    print('iface ' + args.interface + ' Not Found. Please check the arguments!')
    exit()
if os.system('netstat > /dev/null 2>&1') == 32512:
    print('netstat Not Found. Please install net-tools!')
    exit()

pDump = PcapWriter(workDir + 'package.pcap', append=True, sync=True)
sniff(iface=args.interface, prn=lambda p: threading.Thread(
    target=process_sniffed_packet, args=(p,)).start())
