import os
import csv
import yaml


workDir = os.path.dirname(os.path.abspath(__file__)) + '/'


# os.chdir(workDir + 'CICFlowMeter-4.0/bin')
# os.system('./cfm ' + workDir + ' ' + workDir)
# os.remove(workDir + 'package.pcap')
# with open(workDir + 'package.pcap_Flow.csv') as csvFile:
#     rows = csv.reader(csvFile)
#     with open(workDir + 'package_for_training.csv', 'w') as newCsvFile:
#         writer = csv.writer(newCsvFile)
#         for index, row in enumerate(rows):
#             if index:
#                 # row.extend([pid, uid])
#                 row.extend()
#             else:
#                 row.extend(['pid', 'uid'])
#             writer.writerow(row)
# os.remove(workDir + 'package.pcap_Flow.csv')

for f in os.listdir(workDir + 'additions/'):
    with open(workDir + 'additions/' + f, 'r') as yamlFile:
        print(yaml.load(yamlFile))