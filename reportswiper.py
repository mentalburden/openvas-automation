#!/usr/bin/python3
import sys
import getopt
import csv
import re
import subprocess
from io import BytesIO
from lxml import etree

reportpath = "/tmp/"
reportIDs = []
reportNames = []

#----------GNS stuff here
sys.path.append("/usr/local/gnsms/py-lib")
from net.NetSecController import NetSecController
ns = NetSecController()

def shipcsvreport(ip,name,file):
		ns.upload_csv(ip,"vulnscan",file)

def taskID2ReportID():
		create_task = etree.Element('get_tasks')
		xmltocmd = etree.tostring(create_task, pretty_print=True)
		run = subprocess.run(['/usr/bin/omp', '-X',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		chonklet = run.stdout.decode('utf-8')
		parser = etree.XMLParser(remove_blank_text=True)
		root = etree.XML(chonklet, parser)
		for taskid in root.iter("last_report"):
				chonker = str(etree.tostring(taskid))
				stringed = re.findall('"([^"]*)"', chonker)[0]
				reportIDs.append(stringed)


#-------------------------NOTE-----------------------
#-the hashcode for each of the outputs formats-------
#-These hashes are used in the subproc run cmd below-
#5057e5cc-b825-11e4-9d0e-28d24461215b  Anonymous XML
#910200ca-dc05-11e1-954f-406186ea4fc5  ARF
#5ceff8ba-1f62-11e1-ab9f-406186ea4fc5  CPE
#9087b18c-626c-11e3-8892-406186ea4fc5  CSV Hosts
#c1645568-627a-11e3-a660-406186ea4fc5  CSV Results
#6c248850-1f62-11e1-b082-406186ea4fc5  HTML
#77bd6c4a-1f62-11e1-abf0-406186ea4fc5  ITG
#a684c02c-b531-11e1-bdc2-406186ea4fc5  LaTeX
#9ca6fe72-1f62-11e1-9e7c-406186ea4fc5  NBE
#c402cc3e-b531-11e1-9163-406186ea4fc5  PDF
#9e5e5deb-879e-4ecc-8be6-a71cd0875cdd  Topology SVG
#a3810a62-1f62-11e1-9219-406186ea4fc5  TXT
#c15ad349-bd8d-457a-880a-c7056532ee15  Verinice ISM
#50c9950a-f326-11e4-800c-28d24461215b  Verinice ITG
#a994b278-1f62-11e1-96ac-406186ea4fc5  XML
#----------------------------------------------------

def handleIDArray():
		arrayLength = len(reportIDs)
		for i in range(arrayLength):
				thisreportid = str(reportIDs[i])
				#currently using html format hashcode
				run = subprocess.run(['/usr/bin/omp', '-R',thisreportid, '-f', 'c1645568-627a-11e3-a660-406186ea4fc5'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				chonklet = run.stdout.decode('utf-8')
				print(chonklet) # need to parse report for host info

				thisreport = reportpath + "report-" + thisreportid + ".csv"
				file = open(thisreport,"w+")
				file.write(chonklet)
				file.close()
				#write file first to have local backup, dont get csv info from above var
				with open(thisreport,"r") as csvreport:
						csvread = csv.DictReader(csvreport)
						for r in csvread:
								reportip = r["IP"]
								reportname = r["Task Name"]
						shipcsvreport(reportip, reportname, thisreport)


#main starts here
taskID2ReportID()
handleIDArray()
