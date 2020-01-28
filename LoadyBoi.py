#!/usr/bin/python3
import sys
import getopt
import re
import subprocess

from lxml import etree
#from xml.etree.ElementTree import XML

targetip = ''
targetname = ''
targetcomment = ''
targetid = ''
taskid = ''

#input menu for turret to take args from bash and fire a task creation job in openvas (omp) and rapidscan
def menu(argyboi):
        global targetip, targetname, targetcomment
        try:
                opts, args = getopt.getopt(argyboi,"hi:n:c:",["tip=","tname=","tcomment="])
        except getopt.GetoptError:
                print('nope, not that')
                sys.exit(2)
        for opt, arg in opts:
                if opt == '-h':
                        print('help junk here later')
                        sys.exit()
                elif opt in ("-i","--tip"):
                        targetip = arg
                elif opt in ("-n","--tname"):
                        targetname = arg
                elif opt in ("-c","--tcomment"):
                        targetcomment = arg
        print('menu works, heres the output - targetip: ', targetip,';   targetname: ', targetname, ';    target comments: ', targetcomment)
#menu ends

#start omp stuff
def createTarget(targetip, targetname):
        global targetid
        create_target = etree.Element('create_target')
        name = etree.SubElement(create_target, "name")
        host = etree.SubElement(create_target, "hosts")
        name.text = targetname
        host.text = targetip
        xmltocmd = etree.tostring(create_target, pretty_print=True)
        print(xmltocmd)
        run = subprocess.run(['/usr/bin/omp','--xml',xmltocmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        chonklet = run.stdout.decode('utf-8')
        chonker = re.findall('"([^"]*)"', chonklet)[0]
        targetid = chonker
        print(targetid)

def createTask():
        #config id has to be hardcoded, full and fast scan is: daba56c8-73ec-11df-a475-002264764cea
        #will add option to change scan type through cli arg later on - KISS
        global targetid, targetname, targetcomment
        targetidstring = '<root><target id=\"' + targetid + '\" /></root>'
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
        print(run.stdout)
        chonklet = run.stdout.decode('utf-8')
        chonker = re.findall('"([^"]*)"', chonklet)[0]
        taskid = chonker
        print(taskid)



#run menu
if __name__ == "__main__":
        menu(sys.argv[1:])
createTarget(targetip, targetname);
createTask()
