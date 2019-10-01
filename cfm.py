import io
import os
import csv
import time
import yaml
import zipfile
import requests


workDir = os.path.dirname(os.path.abspath(__file__)) + '/'


def download_cfm():
    print('CICFlowmeter Not Found. Downloading...')
    r = requests.get(
        'https://www.unb.ca/cic/_assets/documents/cicflowmeter-4.zip')
    z = zipfile.ZipFile(io.BytesIO(r.content))
    z.extractall(path=workDir)
    os.system('chmod +x ' + workDir + 'CICFlowMeter-4.0/bin/cfm')
    print('Download Complete!')

if os.system('java > /dev/null 2>&1') == 32512:
    print('java Not Found. Please install default-jre!')
    exit()
if os.system('pcap-config > /dev/null 2>&1') == 32512:
    print('pcap-config Not Found. Please install libpcap-dev!')
    exit()
if not os.path.isdir(workDir + 'CICFlowMeter-4.0'):
    download_cfm()

os.chdir(workDir + 'CICFlowMeter-4.0/bin')
if os.system('./cfm ' + workDir + ' ' + workDir) != 256:
    with open(workDir + 'package.pcap_Flow.csv') as csvFile:
        rows = csv.reader(csvFile)
        with open(workDir + 'package_for_training/' + str(time.time()) + '.csv', 'w') as newCsvFile:
            writer = csv.writer(newCsvFile)
            for index, row in enumerate(rows):
                if index:
                    try:
                        timestamp = str(time.mktime(time.strptime(row[6], '%d/%m/%Y %I:%M:%S %p'))).split('.')[0]
                        sport = row[2] if int(row[2]) else '??'
                        dport = row[4] if int(row[4]) else '??'
                        yamlFileName = timestamp + '-' + sport + '-' + dport + '.yml'
                        with open(workDir + 'additions/' + yamlFileName, 'r') as yamlFile:
                            additions = yaml.safe_load(yamlFile)
                            row.extend([additions['pid'], additions['uid'], additions['cmd'], additions['comm']])
                    except:
                        row.extend([None, None, None, None])
                else:
                    row.extend(['pid', 'uid', 'cmd', 'comm'])
                writer.writerow(row)
    os.remove(workDir + 'package.pcap_Flow.csv')
