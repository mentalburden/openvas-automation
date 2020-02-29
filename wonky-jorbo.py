#!/usr/bin/python3


import asyncio as asyncio
import sys
import getopt
import re
import subprocess
from lxml import etree


#------[redacted] stuff here
sys.path.append("/usr/local/[redacted]/py-lib")
from net.NetSecController import NetSecController
ns = NetSecController()


#------Debug Vars here, need cleanup after full integration with the NetSecController and mySqlDBConnector---
outfilepath = '' #nothing or absolute path
cmdToRun = 'nmap -T4 --min-parallelism 1 --max-parallelism 1 -F --open ' #needs a space at the end
iptargets = []
livetargets = []
livehosttasks = []
portscantasks = []
targetids = [] # greenbone target ids for each target, task run needs these
taskids = [] #greenbone task ids


async def runlivehosts(ip):
    #async nmap livehost, no portscan, just checking for live host
    cmd = "nmap -sn " + str(ip.rstrip("\n")) + " -oG - | awk '/Up$/{print $2}'"
    proc = await asyncio.create_subprocess_shell(cmd,stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if stdout:
        chonk = stdout.decode()
        for line in chonk.splitlines():
            livetargets.append(line)
    if stderr:
        print("very broken")
    await asyncio.sleep(0.3)


async def runportscan(ip):
    #async -f --open scan for each livehost, spits textfile
    cmd = cmdToRun + str(ip.rstrip("\n"))
    outfilename = outfilepath+ip.rstrip("\n")+'-nmap-scan.txt'
    print(outfilename)
    nmapoutfile = open(outfilename, "a+")
    proc = await asyncio.create_subprocess_shell(cmd,stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if stdout:
        nmapoutfile.write(stdout.decode())
    if stderr:
        nmapoutfile.write(stderr.decode())
    await asyncio.sleep(10)
    nmapoutfile.close()


async def livescanloopmanager():
    #start livehost scan to clean up actual target list and take care of cidrs
    for i in range(len(iptargets)):
        try:
            livehosttasks.append(i)
            livehosttasks[i] = loop.create_task(runlivehosts(iptargets[i]))
        except IndexError:
            pass
    await asyncio.sleep(0.5)
    for i in range(len(livehosttasks)):
        await livehosttasks[i]


async def portscanloopmanager():
    #start portscans for each livehost
    for i in range(len(livetargets)):
        try:
            portscantasks.append(i)
            portscantasks[i] = loop.create_task(runportscan(livetargets[i]))
        except IndexError:
            pass
    await asyncio.sleep(0.5)
    for i in range(len(portscantasks)):
        await portscantasks[i]


def getTargets():
    for target in ns.get_batch():
        thistarget = target["ipsubnet"] #redo this to grab the entire json and parse it into seperate arrays for each func to use
        iptargets.append(thistarget)


def createGreenBoneTarget(targetip, targetname):
        create_target = etree.Element('create_target')
        name = etree.SubElement(create_target, "name")
        host = etree.SubElement(create_target, "hosts")
        name.text = targetname
        host.text = targetip
        xmltocmd = etree.tostring(create_target, pretty_print=True)
        run = subprocess.run(['/usr/bin/omp','--xml',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chonklet = run.stdout.decode('utf-8')
        chonker = re.findall('"([^"]*)"', chonklet)[2] #grabs the target id and pushes into targetids array
        targetids.append(chonker)


def createGreenBoneTask(id):
        #config id has to be hardcoded, full and fast scan is: daba56c8-73ec-11df-a475-002264764cea
        #will add option to change scan type through cli arg later on - KIS
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

        run = subprocess.run(['/usr/bin/omp','--xml',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chonklet = run.stdout.decode('utf-8')
        print(chonklet)
        chonker = re.findall('"([^"]*)"', chonklet)[2] #grabs the task id and pushes it into the taskids array
        taskids.append(chonker)


def startGreenBoneTask(taskid):
        run = subprocess.run(['/usr/bin/omp','-S', taskid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chonklet = run.stdout.decode('utf-8')
        if chonklet == "None":
            print("Running task: " + taskid)


def runGreenBone():
    print(livetargets) #debug out
    for target in livetargets:
        debugname = "test from new script " + target #debug name, use batch name later on
        createGreenBoneTarget(target, debugname)
    print(targetids) #debug out
    for id in targetids:
        createGreenBoneTask(id) # needs target name and comments from the get_batch, add this later
    print(taskids) #debug out
    for task in taskids:
        startGreenBoneTask(task)


def shipLocalReports():
    print("shipping reports")
    #grab all local nmap reports, ftp/scp out to target volume with net.netSecController


#main starts here
if __name__ == '__main__':
#    readInFile(iplistpath) # debug file read
    getTargets() #using the net.NetSecController stuff
    loop = asyncio.get_event_loop()
    chonker = loop.run_until_complete(livescanloopmanager())
    chonker2 = loop.run_until_complete(portscanloopmanager())
    runGreenBone()
    shipLocalReports()
