import subprocess
import re

def findProfiles(vmemfile):
    checkver = "python vol.py -f " + vmemfile + " imageinfo"
    p = subprocess.Popen(checkver, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    p = p.splitlines()
    profiles = p[0].split(": ")[1].split(", ")
    return profiles

def runCommand(vmemfile, profile, command):
    fullCommand = "python vol.py -f " + vmemfile + " --profile=" + profile + " " + command
    p = subprocess.Popen(fullCommand, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    return p

def viewProcessInfo(pid, vmemfile, os):
    results = runCommand(vmemfile, os, "pslist -p " + pid)
    netscan = Netscan(vmemfile, os)
    netscanResult = netscan[0]
    netscanColumns = netscan[1]

    print "##############################################################################################################################################\n"
    print "##########################################################  Details of Process  ##############################################################"
    print results
    for row in range(0, len(netscanColumns['Pid'])):
        if netscanColumns['Pid'][row] == pid:
            print "#########################################################  Details of Network  ###############################################################\n"
            print netscanResult[0]
            print netscanResult[row+1]

    print "\n##############################################################################################################################################"
    return

###PSLIST Categorisation
def Pslist(vmemfile, os):
    results = runCommand(vmemfile, os, "pslist")
    result = results.splitlines()
    processes = []
    systemcnt = 0
    smsscnt = 0
    lsasscnt = 0
    lsassid = []

    for i in range(2, len(result)):
        row = result[i].split()
        processDetails = []
        for j in range(len(row)):
            if j == 8:
                processDetails.append(row[j])
            elif j == 9 or j == 10:
                processDetails[8] = processDetails[8] + " " + row[j]
            elif j == 11:
                processDetails.append(row[j])
            elif j == 12 or j == 13:
                processDetails[9] = processDetails[9] + " " + row[j]
            else:
                processDetails.append(row[j])


        processes.append(processDetails)
    #0: Offset 1: Name, 2: PID, 3: PPID, 4: Thds, 5: Hnds, 6: Sess, 7: Wow64, 8: Start, 9: Exit


    #Match for unusual process names
    unusual = readFile("data/unusual.txt")
    session_0 = readFile("data/session_0.txt")
    unusualMatch = []
    sessionMatch = []
    notLegit = []


    for process in processes:

        #check if process is a child of any lsass.exe
        for id in lsassid:
            if process[3] == id:
                notLegit.append(process)
                break

        #Check if process System is legitimate
        if process[1] == "System":
            #check if System PID is 4
            if process[2] != "4":
                notLegit.append(process)
            systemcnt += 1

        #Check if process smss.exe is legitimate
        if process[1] == "smss.exe":
            #check if smss.exe parent is System
            if process[3] != "4":
                notLegit.append(process)
            smsscnt += 1

        #Check if process lsass.exe is legitimate
        if process[1] == "lsass.exe":
            lsasscnt += 1
            #save lsassid in a list (list is if in case there is more than 1 lsass.exe)
            lsassid.append(process[2])

        for session_0_Process in session_0:
            if process[1] == session_0_Process:
                if process[6] != "0":
                    sessionMatch.append(process)

        for unusualProcess in unusual:
            if process[1] == unusualProcess:
                unusualMatch.append(process)

        overall = unusualMatch + sessionMatch + notLegit
    while True:
        counter = 1
        if (len(unusualMatch) == 0 and len(sessionMatch) == 0 and len(notLegit) == 0):
            print "No suspicious processes found."
        else:
            if (len(unusualMatch) > 0):
                print "Listing unusual processes:"

                for process in unusualMatch:
                    print str(counter) + ".",
                    print process
                    counter += 1

                print

            if (len(sessionMatch) > 0):
                print "These processes are supposed to run as session 0:"

                for process in sessionMatch:
                    print str(counter) + ".",
                    print process
                    counter += 1

                print

            if (len(notLegit) > 0):
                print "These processes might not be legitimate:"

                for process in notLegit:
                    print str(counter) + ".",
                    print process
                    counter += 1

                print

        print str(counter) + ". " + "Go back"
        choice = int(raw_input("Do you want to zoom in on a process? "))
        if choice > counter:
            print "Wrong selection"
        elif choice == counter:
            print "Going back"
            break
        else:
            ##can run other plugins to do a detailed analysis on specified process
            viewProcessInfo(overall[choice - 1][2], vmemfile, os)

            if systemcnt > 1:
                print "More than 1 System process found, might be a malicious process"
    return

###PSXVIEW Categorisation
def Psxview(vmemfile, os):
   results = runCommand(vmemfile, os, "psxview")
   result = results.splitlines()
   processes = []
   for i in range(2, len(result)):
       row = result[i].split()
       processDetails = []
       for j in range(len(row)):
           if j == 10:
               processDetails.append(row[j])
           elif j == 11 or j == 12:
               processDetails[10] = processDetails[10] + " " + row[j]
           else:
               processDetails.append(row[j])

       processes.append(processDetails)
   #0: Offset 1: Name, 2: PID, 3: PPID, 4: Thds, 5: Hnds, 6: Sess, 7: Wow64, 8: Start, 9: Exit
   return processes

###NETSCAN Categorisation
def Netscan(vmemfile, os):
    results = runCommand(vmemfile, os, "netscan")
    result = results.splitlines()
    #result[0] = heading
    '''
    outfd.write("{0:<18} {1:<8} {2:<30} {3:<20} {4:<16} {5:<8} {6:<14} {7}\n".format(
            self.offset_column(), "Proto", "Local Address", "Foreign Address",
            "State", "Pid", "Owner", "Created"))
    '''

    columns = {}
    columns['Offset'] = []
    columns['Protocol'] = []
    columns['Local Address'] = []
    columns['Foreign Address'] = []
    columns['State'] = []
    columns['Pid'] = []
    columns['Owner'] = []
    columns['Created'] = []


    #Dictionary with key as column, list for each row under the specified column
    for line in range(1,len(result)):
        columns['Offset'].append(result[line][8:].strip())
        columns['Protocol'].append(result[line][19:][:8].strip())
        columns['Local Address'].append(result[line][28:][:30].strip())
        columns['Foreign Address'].append(result[line][59:][:20].strip())
        columns['State'].append(result[line][80:][:16].strip())
        columns['Pid'].append(result[line][97:][:8].strip())
        columns['Owner'].append(result[line][106:][:14].strip())
        columns['Created'].append(result[line][-28:])

    return result, columns


def NetscanFlagged(vmemfile, os):
    netscan = Netscan(vmemfile, os)
    result = netscan[0]
    columns = netscan[1]
    common = readFile("data/common.txt")
    unusual = readFile("data/unusual.txt")
    # to store flagged processes
    flagged = []
    for row in range(0, len(result)-1):
        if columns['Foreign Address'][row] != "":
             if columns['Foreign Address'][row] != "*:*":
                 if columns['Foreign Address'][row] != ":::0":
                     if columns['Foreign Address'][row] != "0.0.0.0:0":
                        for commonService in common:
                            if columns['Owner'][row] == commonService:
                                flagged.append(result[row+1])
                        for unusualProcess in unusual:
                            if columns['Owner'][row] == unusualProcess:
                                flagged.append(result[row+1])

    if len(flagged) == 0:
        print "No suspicious network activity found."
        print
    else:
        while True:
            counter = 1
            print "Listing suspicious network activity:"
            print "   " + result[0]
            for process in flagged:
                print str(counter) + ". " + process
                counter += 1
            print str(counter) + ". Go back"
            choice = int(raw_input("Do you want to zoom in on a process? "))
            if choice > counter:
                print "Wrong selection"
            elif choice == counter:
                print "Going back"
                break
            else:
                ##can run other plugins to do a detailed analysis on specified process
                viewProcessInfo(flagged[choice-1][97:][:8].strip(), vmemfile, os)


    return

##Printkey Categorisation
def printRegistryKeys(vmemfile, os):
    path = readFile("data\commonMalwareRegistry.txt")

    for i in path:
        print i
        if i == '':
            continue
        command = "printkey -K " + "\"" + i + "\""
        keyResults = runCommand(vmemfile, os, command)
        row = keyResults.splitlines()
		
        if len(row) == 0:
            print 'Key not found in the hives'
        for w in range(len(row)):
            if row[2] != '----------------------------':
                print 'Key not found in the hives'
                break
            elif row[w] == 'Values:' and row[w] is row[-1]:
                # print 'last'
                print 'No suspicious program found'
                break

            elif row[w] == 'Values:':
                valueRow = row[w + 1].split() # further split the elements in values list to check if registry data is base64
                if row[w+1] == '----------------------------':
                    continue
                elif re.match('^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$', valueRow[4]): # check if base64
                    print "\nSuspicious program found:"
                    print row[w-6]  # print values aka suspected malicious software
                    print row[w+1] + "\n###########################################################################"  # print registry containing that value



def readFile(filename):
    lines = []
    fp = open(filename, 'r')

    for i in fp:
        lines.append(i[:-1])

    fp.close()

    return lines



def main():
    #Input for vmem file
    vmemfile = raw_input("Enter vmem file to analyse: ")
    os = ""
    while True:

        findProfile = raw_input("Would you like to search for possible profiles? (y/n): ")

        if findProfile == "n":
            os = raw_input("Enter profile name: ")
            print "Using profile " + os
            break
        elif findProfile == "y":

            count = 1
            profiles = findProfiles(vmemfile)
            for profile in profiles:
                print str(count) + ".",
                print profile
                count += 1
            select = raw_input("Which profile would you like to use?: ")
            os = profiles[int(select)-1]
            print "Using profile " + os
            break

        else:
            print "Please enter either y or n."


    commands = ["Check for suspicious processes",
                "Check for hidden processes",
                "Check for suspicious network activity",
                "Check common registry locations for malware",
                "Self specify a plugin", "Exit"]
    while True:
        print "Choose a command to run"
        for i in range(len(commands)):
            print str(i+1) + ". " + commands[i]

        command = raw_input()
        if commands[int(command)-1] == "Exit":
            print "Exiting.."
            exit()

        elif commands[int(command)-1] == "Self specify a plugin":
            other_command = raw_input("Enter plugin to use: ")
            results = runCommand(vmemfile, os, other_command)
            print results

        elif commands[int(command) - 1] == "Check for suspicious processes":
            Pslist(vmemfile, os)

        elif commands[int(command) - 1] == "Check for hidden processes":
            count = 0
            processes = Psxview(vmemfile, os)
            for i in processes:
                if i[3] == "False" and i[4] == "True" and len(i) == 10:
                    count += 1
                    print "Process " + i[1] + " with PID " + i[
                        2] + " is trying to hide itself and further investigation is needed."
            if count == 0:
                print "No hidden processes detected."

        elif commands[int(command) - 1] == "Check for suspicious network activity":
            NetscanFlagged(vmemfile, os)

        elif commands[int(command) - 1] == "Check common registry locations for malware":
            printRegistryKeys(vmemfile, os)

        else:
            print "Wrong input"

main()