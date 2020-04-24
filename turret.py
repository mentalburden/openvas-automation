#!/usr/bin/python3

import asyncio as asyncio
import ipaddress as ipaddr
import socket
import sys
import getopt
import re
import subprocess
from lxml import etree

#------library stuff here
sys.path.append("/usr/local/library/py-lib")
from net.NetSecController import NetSecController
ns = NetSecController()

#------Debug Vars here, need cleanup after full integration with the NetSecController and mySqlDBConnector---
outfilepath = '/tmp/' #nothing or absolute path
cmdToRun = 'nmap -T4 --min-parallelism 1 --max-parallelism 1 -F --open ' #needs a space at the end
iptargets = []
livetargets = []
livehosttasks = []
portscantasks = []
targetids = [] # greenbone target ids for each target, task run needs these
taskids = [] #greenbone task ids
reportids = []
reportnames = []


#--------Report handling here


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
				reportids.append(stringed)


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


def handlereportIDs():
		arrayLength = len(reportids)
		for i in range(arrayLength):
				thisreportid = str(reportids[i])
				#currently using html report hash
				run = subprocess.run(['/usr/bin/omp', '-R',thisreportid, '-f', 'c1645568-627a-11e3-a660-406186ea4fc5'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				chonklet = run.stdout.decode('utf-8')
				reportstring = "/tmp/reportdebugout/report-" + thisreportid + ".csv"
				file = open(reportstring,"w+")
				file.write(chonklet)
				file.close()

#-------------Target handling here


def livehostcheck(ip):
		debugports = [21,22,25,80,443,4365]
		debugbanners = [b'GET / HTTP/1.1\n Banner grab test, dont mind me.\n\n']
		for x in range(len(debugports)):
				socket.setdefaulttimeout(1)
				bangrab = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
				try:
						bangrab.connect((ip,debugports[x]))
						bangrab.send(b'GET / HTTP/1.1\n Banner grab test, dont mind me.\n\n') #match/map ports to banners and step through indexes together
						ban = bangrab.recv(511)
						bangrab.close()
						if (len(ban) > 1):
								print("debug: " +str(ip) + ":" + str(debugports[x]) + "   banner: " + str(ban))
								return str(ip)
				except:
						print(".")


def processTargets():
		for target in ns.get_batch():
				thistarget = target["ipsubnet"]
				for addr in ipaddr.IPv4Network(thistarget):
						chonk = livehostcheck(str(addr))
						if (chonk != None):
								livetargets.append(chonk) #live targets needs to be a json to handle the batchid as well


def createGreenBoneTarget(targetip, targetname):
		create_target = etree.Element('create_target')
		name = etree.SubElement(create_target, "name")
		host = etree.SubElement(create_target, "hosts")
		alive = etree.SubElement(create_target, "alive_tests")
		name.text = targetname
		host.text = targetip
		alive.text = "ICMP & TCP-ACK Service Ping"
		xmltocmd = etree.tostring(create_target, pretty_print=True)
		try:
				run = subprocess.run(['/usr/bin/omp','--xml',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				chonklet = run.stdout.decode('utf-8')
				chonker = re.findall('"([^"]*)"', chonklet)[2] #grabs the target id and pushes into targetids array
				targetids.append(chonker)
		except:
				print(chonklet)


def createGreenBoneTask(id):
		#config id has to be hardcoded, full and fast scan is: daba56c8-73ec-11df-a475-002264764cea
		targetname = "test from new script" # debug cheat, fix later to use batch name
		targetcomment = "test comment beep boop" # debug cheat, fix later to use batch comment (if avail)
		targetidstring = '<root><target id=\"' + id + '\" /></root>'
		configidstrong = '<root><config id="daba56c8-73ec-11df-a475-002264764cea" /></root>'
		mytargetid = etree.XML(targetidstring)
		myconfigid = etree.XML(configidstrong)
		taskname = "Script generated task for: " + targetname
		create_task = etree.Element('create_task')
		name = etree.SubElement(create_task, "name")
		comment = etree.SubElement(create_task, "comment")
		configid = etree.SubElement(create_task, "config")
		name.text = taskname
		comment.text = targetcomment
		create_task.extend(myconfigid)
		create_task.extend(mytargetid)
		xmltocmd = etree.tostring(create_task, pretty_print=True)
		try:
				run = subprocess.run(['/usr/bin/omp','--xml',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				chonklet = run.stdout.decode('utf-8')
				chonker = re.findall('"([^"]*)"', chonklet)[2] #grabs the task id and pushes it into the taskids array
				taskids.append(chonker)
		except:
				print(chonklet)


def startGreenBoneTask(taskid):
		run = subprocess.run(['/usr/bin/omp','-S', taskid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		chonklet = run.stdout.decode('utf-8')
		if chonklet != "None":
				print("Running task: " + taskid)


def runGreenBone():
		print(livetargets) #debug out
		for target in livetargets:
				debugname = "test-" + str(target) #debug name, use batch name later on
				createGreenBoneTarget(target, debugname)
		print(targetids) #debug out
		for id in targetids:
				createGreenBoneTask(id) # needs target name and comments from the get_batch, add this later
		print(taskids) #debug out
		for task in taskids:
				startGreenBoneTask(task)


def runReports():
		taskID2ReportID()
		handlereportIDs()

#main starts here
if __name__ == '__main__':
#	   runReports()
		processTargets() #using the net.NetSecController stuff
		runGreenBone()
