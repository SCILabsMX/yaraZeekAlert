#!/usr/bin/python
''' Based on the script by David Bernal Michelena - SCILabs, 2019
Name: yaraZeekAlert.py
Author 2019 : David Bernal Michelena - SCILabs
Author 2023 : Eduardo P. Sánchez DS 
License: CREATIVE COMMONS LICENSE BY-NC https://creativecommons.org/licenses/by-nc/4.0/

Description:
This script scans the files extracted by Zeek with YARA rules located on the rules folder on a Linux based Zeek sensor, if there is a match it sends email alerts to the email address specified in the mailTo parameter on yaraAlert.conf file. The alert includes network context of the file transfer and attaches the suspicious file if it is less than 10 MB. Alerted files are copied locally to the alerted files folder.
This version is for python 3.10

A Sample yaraAlert.conf configuration file is provided below, this file should be in the same folder than this script.
mailUsername=DOMAIN\username
mailPassword=password
mailServer=mail server IP address
mailPort=25
mailDisplayFrom=bro@domain.com
mailTo=securityteam@domain.com
'''

import subprocess
import os
import time
import sys
import hashlib
import smtplib
import glob
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Change the following variables based on your own configuration
alertedFilesFolder =  "/home/bro/YARA/alertedFiles"
extractedFilePath = "/home/bro/extracted"
yaraRulesPath = "/home/bro/YARA/rules"
sevenZipCommand = "/bin/7za"
yaraAlertConfigFile = "/home/bro/YARA/yaraAlert.conf" 

if not os.path.isfile(yaraAlertConfigFile):
    print("file does not exist: " + yaraAlertConfigFile)
    sys.exit(1)

with open(yaraAlertConfigFile, "r") as f:
    for line in f:
        lineLst = line.strip("\n").split("=")
        if lineLst[0] in "mailUsername":
            broMailUsername = lineLst[1]
        elif lineLst[0] in "mailPassword":
            broMailPassword = lineLst[1]
        elif lineLst[0] in "mailServer":
            mailServer = lineLst[1]
        elif lineLst[0] in "mailPort":
            mailPort = lineLst[1]
        elif lineLst[0] in "mailDisplayFrom":
            mailDisplayFrom = lineLst[1]
        elif lineLst[0] in "mailTo":
            mailTo = lineLst[1]

def hashes(fname):
    md5 = hashlib.md5(open(fname, 'rb').read()).hexdigest()
    sha1 = hashlib.sha1(open(fname, 'rb').read()).hexdigest()
    sha256 = hashlib.sha256(open(fname, 'rb').read()).hexdigest()
    return [md5, sha1, sha256]

def searchContext(searchPath, pattern, archived):
    flog = open("/home/bro/YARA/actions.log", "w+")
    flog.write("searching for pattern: " + pattern + " in " + searchPath)

    out = ""
    currentLogPath = "/home/bro/logs/current"
    
    if not archived:
        files = glob.glob(searchPath + "/*.log")
    else:
        files = glob.glob(searchPath + "/*.log.gz")
    
    for f in files:
        flog.write("searching in " + f)

        if not archived:
            command = "/bin/cat " + f + " | /usr/local/bro/bin/bro-cut -d | grep " + pattern + " "
            flog.write("command :" + command)
        else:
            command = "/bin/zgrep " + pattern + " " + f
            flog.write("command :" + command)
            print(command)

        try:
            flog.write("before appending \n" + out)
            out += subprocess.check_output(command, shell=True).decode('utf-8')
            flog.write("after appending \n" + out)
        except:
            pass
    
    print("context found in path: " + searchPath)
    flog.write("context found in path: \n" + searchPath)

    if out == "":
        out = "Context not found in current logs \n"

    print(out)
    flog.write("output: " + out)
    return out

def sendAlertEmail(message, fromaddr, recipient, filepath, context):
    toaddr = recipient

    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = recipient
    msg['Subject'] = "YARA Alert"

body = "alerted rules: " + str(message[0]) + "\n"
body += "filepath: " + str(message[1]) + "\n"
body += "md5sum : " + str(message[2]) + "\n"
body += "sha1sum: " + str(message[3]) + "\n"
body += "sha256sum: " + str(message[4]) + "\n\n"

filename = filepath.split("/")[-1]    
generatedZip = alertedFilesFolder + "/" + filename + ".zip"
print("generatedZip: " + generatedZip)

if os.path.isfile(generatedZip):
	os.remove(generatedZip)

rc = subprocess.call([sevenZipCommand, 'a', '-pinfected', '-y', generatedZip, filepath])
