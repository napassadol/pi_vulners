from sqlalchemy import create_engine, create_engine, and_
from sqlalchemy.orm import sessionmaker
import datetime
import sqlModel
import vulners
import re
import time
import subprocess

engine = create_engine('mysql+pymysql://networkscan:12341234@128.199.195.239/network_scan', echo = True)

Session = sessionmaker(bind=engine)

vulners_api = vulners.Vulners(api_key="7NNARV5RD6U90AQ18CKWQSSLDOAOTHCSTATMHKYZNDQC2DJD7VTCVAVVI0MB2QHO")

# output_path = 'scan2.text'

def getOutput():
    command = 'nmap -sV --script=vulscan/vulscan.nse --script-args vulscandb=cve.csv 192.168.1.0/24'
    process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    output = process.stdout
    # f = open(output_path, "r")
    # text = f.read()
    # print(text)
    return output

def readCVEData(text):
    global cve
    result = {}
    port = ''
    state = ''
    service = ''
    ip = ''
    lines = text.split('\n')
    for line in lines:
        if 'Nmap scan report for' in line:
            regex = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
            ip = regex[0]
            result[ip] = {}
        elif '/tcp' in line and '|' not in line:
            listStr = [x for x in line.split(" ") if x != '']
            port = listStr[0]
            state = listStr[1]
            service = listStr[2]
            result[ip][port] = {}
        else:
            regex = re.findall(r"\[(.*?)\]", line)
            if len(regex):
                cveText = regex[0]
                result[ip][port][cveText] = {}

    for key, value in result.items():
        for key2, value2 in result[key].items():
            listCve = [x for x, y in value2.items()]
            CVE_DATA = vulners_api.documentList(listCve)
            for item in CVE_DATA:
                result[key][key2][item] = CVE_DATA[item]
                result[key][key2][item]['service'] = service
                result[key][key2][item]['state'] = state
    
    return result

def insertNmap(data, scanData):
    session = Session()
    nmapList = []
    cvssList = []
    for ip in data:
        for port in data[ip]:
            for key, val in data[ip][port].items():
                nmap = sqlModel.Nmap(
                    ip = ip,
                    port = port,
                    score = val['cvss']['score'],
                    severity = val['cvss2']['severity'],
                    cve = val['id'],
                    cwe = val['cwe'][0],
                    des = val['description'],
                    vector = val['cvss']['vector'],
                    scan_id = scanData.id,
                    state = val['state'],
                    service = val['service']
                )
                nmapList.append(nmap)
                cvssList.append(insertCvss2(val['cvss2']['cvssV2'], 0))

    session.add_all(nmapList)
    session.commit()
    print('---------------------')
    print(len(nmapList))
    print('---------------------')
    for i in range(len(nmapList)):
        cvssList[i].nmap_id = nmapList[i].id
    session.add_all(cvssList)
    session.commit()

def insertScan(scanType='nmap'):
    session = Session()
    scanData = sqlModel.Scan(
        name=scanType + '-' + str(int(datetime.datetime.timestamp(datetime.datetime.now()))),
        scan_type=scanType
    )
    session.add(scanData)
    session.commit()
    return scanData

def insertCvss2(data, nmap_id):
    # session = Session()
    cvss = sqlModel.Cvss(
        version = 2.0,
        accessComplexity = data['accessComplexity'],
        accessVector = data['accessVector'],
        authentication = data['authentication'],
        availabilityImpact = data['availabilityImpact'],
        baseScore = data['baseScore'],
        confidentialityImpact = data['confidentialityImpact'],
        integrityImpact = data['integrityImpact'],
        vectorString = data['vectorString'],
        nmap_id = nmap_id
    )
    # session.add(cvss)
    # session.commit()
    return cvss

def getSeverity(scan_id):
    session = Session()
    low = session.query(sqlModel.Nmap).filter(and_(sqlModel.Nmap.severity == 'LOW', sqlModel.Nmap.scan_id == scan_id)).count()
    medium = session.query(sqlModel.Nmap).filter(and_(sqlModel.Nmap.severity == 'MEDIUM', sqlModel.Nmap.scan_id == scan_id)).count()
    high = session.query(sqlModel.Nmap).filter(and_(sqlModel.Nmap.severity == 'HIGH', sqlModel.Nmap.scan_id == scan_id)).count()
    print('low: {}, medium: {}, high: {}'.format(str(low), str(medium), str(high)))
    return low, medium, high
