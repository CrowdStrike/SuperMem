###############################################################################
## SuperMem for Windows Memory Analysis v1.0
## Written by James Lovato - CrowdStrike
## Copyright 2021 CrowdStrike, Inc.
###############################################################################

import threading
import queue
import tqdm
import os
import re
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
import subprocess
import time
import csv
import logging
import ipaddress
import sys
from termcolor import colored

# Globals Likely Needing Updated
THREADCOUNT = 12
EVTXTRACTPATH = "/usr/local/bin/evtxtract"
VOL3PATH = "/usr/bin/vol3"
VOL2PATH = "/usr/bin/vol.py"
VOL2EXTRAPLUGINS = "/usr/share/volatility/plugins/community/"
BULKPATH = "/usr/bin/bulk_extractor"
LOG2TIMELINEPATH = "/usr/bin/log2timeline.py"
PSORTPATH = "/usr/bin/psort.py"
YARAPATH = "/usr/bin/yara"
STRINGSPATH = "/bin/strings"
YARARULESFILE = "/path/to/yara/Yarafile.txt"

# Globals for Output Files and Paths
VOL3outputDir = "Volatility3"
VOL2outputDir = "Volatility2"
BEoutputDir = "BEoutputDir"
STRINGSoutputDir = "Strings"
DUMPFILESoutputDir = "DumpedFilesOutput"
DUMPDLLSoutputDir = "DumpedDllsOutput"
DUMPPROCESSESoutputDir = "DumpedProcessOutput"
DUMPMODULESoutputDir = "DumpedModules"
DUMPREGISTRYoutputDir = "DumpedRegistry"
DUMPEVTXoutputDir = "Evtxtract"
LOGGINGOUTPUT = "Logging.log"
IOCOUTPUT = "IOCs.csv"
PLASOOUTPUT = "Plaso"
YARAoutputDir = "Yara"

# Volatility3 Plugins for Quick Triage
QUICKTRIAGEPLUGINS = [{"plugin": "windows.pstree.PsTree", "params": ""},
                      {"plugin": "windows.cmdline.CmdLine", "params": ""},
                      {"plugin": "windows.callbacks.Callbacks", "params": ""},
                      {"plugin": "windows.svcscan.SvcScan", "params": ""},
                      {"plugin": "windows.registry.userassist.UserAssist", "params": ""},
                      {"plugin": "windows.envars.Envars", "params": ""},
                      {"plugin": "windows.handles.Handles", "params": ""},
                      {"plugin": "windows.modules.Modules", "params": ""},
                      {"plugin": "windows.dlllist.DllList", "params": ""},
                      {"plugin": "windows.getsids.GetSIDs", "params": ""},
                      {"plugin": "windows.getservicesids.GetServiceSIDs", "params": ""},
                      {"plugin": "windows.malfind.Malfind", "params": ""},
                      {"plugin": "windows.pslist.PsList", "params": ""},
                      {"plugin": "windows.registry.hivelist.HiveList", "params": ""},
                      {"plugin": "windows.ssdt.SSDT", "params": ""},
                      {"plugin": "windows.registry.hivescan.HiveScan", "params": ""}]

# Volatility3 Plugins for Full Triage
FULLTRIAGEPLUGINS = [{"plugin": "windows.modscan.ModScan", "params": ""},
                     {"plugin": "windows.mutantscan.MutantScan", "params": ""},
                     {"plugin": "windows.psscan.PsScan", "params": ""},
                     {"plugin": "windows.driverscan.DriverScan", "params": ""},
                     {"plugin": "windows.symlinkscan.SymlinkScan", "params": ""},
                     {"plugin": "windows.driverirp.DriverIrp", "params": ""},
                     {"plugin": "windows.netscan.NetScan", "params": ""},
                     {"plugin": "windows.filescan.FileScan", "params": ""},
                     {"plugin": "windows.poolscanner.PoolScanner", "params": ""}]

# Additional Volatility2 Plugins
VOL2PLUGINS = [{"plugin": "amcache", "params": ""}, {"plugin": "getsids", "params": ""},
               {"plugin": "clipboard", "params": ""},
               {"plugin": "cmdscan", "params": ""}, {"plugin": "consoles", "params": ""},
               {"plugin": "ldrmodules", "params": "--verbose"},
               {"plugin": "mftparser", "params": "--output=body "}, {"plugin": "psxview", "params": "--apply-rules"},
               {"plugin": "shellbags", "params": "--output=body"}, {"plugin": "shutdowntime", "params": ""},
               {"plugin": "indx", "params": "--output=body"}, {"plugin": "logfile", "params": "--output=body"},
               {"plugin": "prefetchparser", "params": "--full_paths"}, {"plugin": "schtasks", "params": ""},
               {"plugin": "sessions", "params": ""}, {"plugin": "shimcachemem", "params": "--output=csv"},
               {"plugin": "shimcache", "params": ""}, {"plugin": "sockets", "params": ""},
               {"plugin": "sockscan", "params": ""}, {"plugin": "threads", "params": ""},
               {"plugin": "usnjrnl", "params": "--output=body"}, {"plugin": "autoruns", "params": "-v"},
               {"plugin": "connections", "params": ""}, {"plugin": "connscan", "params": ""},
               {"plugin": "hollowfind", "params": ""}, {"plugin": "malthfind", "params": ""},
               {"plugin": "timeliner", "params": "--output=body"}, {"plugin": "apihooks", "params": "--quick"}, {"plugin": "messagehooks", "params": ""}]


# Logic for Printing to Console and Logging with Progress Bars
def printLoggingLogic(message, pbar, typeOfLogging, color="green"):
    if typeOfLogging == "INFO":
        logging.info(message)
        if pbar:
            pbar.write(colored("INFO: " + message, color))
        else:
            print(colored("INFO: " + message, color))
    elif typeOfLogging == "ERROR":
        logging.error(message)
        if pbar:
            pbar.write(colored("ERROR: " + message, color))
        else:
            print(colored("ERROR: " + message, color))


# Setup Muli-Threading and Progress Bar
def threadPbar(input, description):
    # Define queue
    inputQueue = queue.Queue(maxsize=0)

    # Add items to queue
    for item in input:
        inputQueue.put(item)

    # Setup progress bar
    pbar = tqdm.tqdm(total=inputQueue.qsize(), desc=description, unit="Command")

    # Create threads for processing
    threads = []
    for i in range(THREADCOUNT):
        t = threading.Thread(target=worker, args=(inputQueue, pbar))
        threads.append(t)
        t.start()

    # Wait for threads to finish
    for thread in threads:
        thread.join()

    pbar.set_description(description + " Complete")
    pbar.close()


# Thread Worker Function
def worker(inputQueue, pbar):
    while not inputQueue.empty():
        data = inputQueue.get()
        commandName = data['Name']
        cmd = data['CMD']
        printLoggingLogic("Started " + commandName, pbar, "INFO")
        startTime = time.time()
        runCMD(cmd, commandName)
        executionTime = (time.time() - startTime)
        pbar.update(1)
        printLoggingLogic("Finished " + commandName + " in " + str(int(executionTime)) + " seconds", pbar, "INFO")


# Run Raw OS Commands
def runCMD(cmd, commandName):
    try:
        logging.info(cmd) # Log Command Ran
        os.system(cmd)
    except Exception as e:
        logging.error("Command " + commandName + " caused the exception: " + str(e)) # Log Any Errors


# Add Volatility Commands to Queue
def volatility3Queue(chosenPlugins, memFullPath, outputDir):
    output = []
    vol3outputDir = os.path.join(outputDir, VOL3outputDir)

    # Create Output Directory
    if not os.path.isdir(vol3outputDir):
        os.mkdir(vol3outputDir)

    # Used to Only Download the PDB Once
    printLoggingLogic("Setting up symbols for Volatility3 with windows.info.Info", False, "INFO")
    pluginName = "windows.info.Info"
    cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -r csv " + pluginName + " 2> " \
          + os.path.join(vol3outputDir, pluginName + ".err") + " > " + os.path.join(vol3outputDir,
                                                                                    pluginName + ".csv")
    runCMD(cmd, "Volatility3 plugin windows.info.Info")

    # Volatility3 Command Creation
    for p in chosenPlugins:
        pluginName = p['plugin']
        params = p['params']
        cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -r csv " + pluginName + " " + params + " 2> " \
              + os.path.join(vol3outputDir, pluginName + ".err") + " > " + os.path.join(vol3outputDir,
                                                                                        pluginName + ".csv")
        data = {'Name': "Volatility3 plugin " + pluginName, 'CMD': cmd}
        output.append(data)

    return output


# Add Bulk Extractor Command to Queue
def bulkExtractorQueue(outputDir, memFullPath):
    output = []
    bulkOutput = os.path.join(outputDir, BEoutputDir)

    # Create Output Directory
    if not os.path.isdir(bulkOutput):
        os.mkdir(bulkOutput)

    # Run Bulk Extractor with Default Parameters
    cmd = BULKPATH + " -o " + bulkOutput + " \"" + memFullPath + "\" > /dev/null 2>&1"
    data = {'Name': 'Bulk Extractor', 'CMD': cmd}
    output.append(data)

    return output


# Add EVTXtract Command to Queue
def evtxtractQueue(outputDir, memFullPath):
    output = []
    evtxOutput = os.path.join(outputDir, DUMPEVTXoutputDir)

    # Get File Name
    memFileName = memFullPath.split('/')[len(memFullPath.split('/')) - 1]

    # Create Output Directory
    if not os.path.isdir(evtxOutput):
        os.mkdir(evtxOutput)

    # EVTXtract Command Creation
    cmd = EVTXTRACTPATH + " \"" + memFullPath + "\" 2> " + os.path.join(evtxOutput, memFileName + ".err") \
          + " > " + os.path.join(evtxOutput, memFileName + ".txt")
    data = {'Name': 'EVTXTRACT', 'CMD': cmd}
    output.append(data)

    return output


# Add Strings Commands to Queue
def stringsQueue(memFullPath, outputDir):
    output = []
    stringsoutputDir = os.path.join(outputDir, STRINGSoutputDir)

    # Get File Name
    memFileName = memFullPath.split('/')[len(memFullPath.split('/')) - 1]

    # Create Output Directory
    if not os.path.isdir(stringsoutputDir):
        os.mkdir(stringsoutputDir)

    # Individual Strings Command Creation
    cmd = STRINGSPATH + " -td -el -a \"" + memFullPath + "\" > " + os.path.join(stringsoutputDir, memFileName + ".strings.unicode")
    data = {'Name': 'Strings unicode', 'CMD': cmd}
    output.append(data)
    cmd = STRINGSPATH + " -td -a \"" + memFullPath + "\" > " + os.path.join(stringsoutputDir, memFileName + ".strings.ascii")
    data = {'Name': 'Strings ascii', 'CMD': cmd}
    output.append(data)
    cmd = STRINGSPATH + " -td -eb -a \"" + memFullPath + "\" > " + os.path.join(stringsoutputDir, memFileName + ".strings.be")
    data = {'Name': 'Strings big endian', 'CMD': cmd}
    output.append(data)

    return output


# Add Volatility2 Commands to Queue
def volatility2Queue(chosenPlugins, memFullPath, outputDir, vol2Profile):
    output = []
    vol2outputDir = os.path.join(outputDir, VOL2outputDir)

    # Create Output Directory
    if not os.path.isdir(vol2outputDir):
        os.mkdir(vol2outputDir)

    # Identify Profile, KDGB, and DTB Values for Volatility2 Processing
    try:
        profilesRex = ""
        cmdOutput = ""

        if not vol2Profile:
            printLoggingLogic("Locating profile, DTB, and KDGB for Volatility2", False, "INFO")
            cmdOutput = subprocess.run([VOL2PATH, '-f', memFullPath, 'imageinfo'],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')
            profilesRex = re.search('Suggested Profile\(s\) : (.+)', cmdOutput, re.IGNORECASE)
        else:
            printLoggingLogic("Locating kdbg and DTB for VOL2", False, "INFO")
            cmdOutput = subprocess.run([VOL2PATH, '-f', memFullPath, 'imageinfo', '--profile=' + vol2Profile],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode('utf-8')

        kdbgRex = re.search('KDBG : (.+?)L', cmdOutput, re.IGNORECASE)
        dtbRex = re.search('DTB : (.+?)L', cmdOutput, re.IGNORECASE)
        kdbg = ""
        dtb = ""
        profile = ""

        # Find Profile
        if not vol2Profile:
            if profilesRex:
                profile = profilesRex.group(1)
                if ',' in profile:
                    profile = profile.split(',')[0]  # Take the first profile if multiple are suggested
            else:
                printLoggingLogic("Cant find profile for Volatility2", False, "ERROR", "red")
                return []
        else:
            profile = vol2Profile

        # Find KDGB
        if kdbgRex:
            kdbg = kdbgRex.group(1)
        else:
            printLoggingLogic("Cant find KDGB for Volatility2 caused by error in regex", False, "ERROR", "red")
            return []

        # Find DTB
        if dtbRex:
            dtb = dtbRex.group(1)
        else:
            printLoggingLogic("Cant find DTB for Volatility2 caused by error in regex", False, "ERROR", "red")
            return []

        # Write Output to File
        imageinfoFile = open(os.path.join(vol2outputDir, "imageinfo.txt"), 'w')
        imageinfoFile.write(cmdOutput)
        imageinfoFile.close()

        # Add Volatility2 Plugins to Queue
        for p in chosenPlugins:
            pluginName = p['plugin']
            params = p['params']
            cmd = VOL2PATH + " --plugins=" + VOL2EXTRAPLUGINS + " -f " + '\"' + memFullPath + '\"' + " --profile=" \
                  + profile + " --kdbg=" + kdbg + " --dtb=" + dtb + " " + pluginName + " " + params + " --output-file=" \
                  + os.path.join(vol2outputDir, pluginName + ".out") + " 2> " \
                  + os.path.join(vol2outputDir, pluginName + ".stderr") + " > " + os.path.join(vol2outputDir,
                                                                                            pluginName + ".stdout")
            data = {'Name': "Volatility2 plugin " + pluginName, 'CMD': cmd}
            output.append(data)

    except Exception as e:
        printLoggingLogic(str(e), False, "ERROR", "red")

    return output


# Dump Files Cached in Memory
def dumpFilesQueue(outputDir, memFullPath, filetypes, filepaths):
    output = []
    filescanOutput = os.path.join(outputDir, VOL3outputDir)
    filescanFullPath = os.path.join(filescanOutput, "windows.filescan.FileScan.csv")
    dumpFilesDir = os.path.join(outputDir, DUMPFILESoutputDir)

    # Create Output Directory
    if not os.path.isdir(dumpFilesDir):
        os.mkdir(dumpFilesDir)

    # Create Command to Dump Certain Files Cached in Memory
    try:
        if os.path.isfile(filescanFullPath):
            filescanobj = open(filescanFullPath, 'r')
            csvfilescanobj = csv.DictReader(filescanobj)

            # Loop Through Volatility3 File Scan Output
            for row in csvfilescanobj:
                exportfilename = row["Name"]
                if exportfilename:
                    exportfilename = exportfilename.lower()
                    if exportfilename.endswith(tuple(filetypes)) or (
                            "\\".join(exportfilename.split('\\')[:-1]) in filepaths) or len(filetypes) == 0:
                        virtAddr = row["Offset"]
                        cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -o " + dumpFilesDir + \
                              " windows.dumpfiles.DumpFiles --virtaddr " + virtAddr + " > /dev/null 2>&1"
                        data = {'Name': "File Dumping for File " + exportfilename, 'CMD': cmd}
                        output.append(data)
        else:
            printLoggingLogic("Cant Find File " + filescanFullPath, False, "ERROR", "red")
    except Exception as e:
        printLoggingLogic("Error in dumpFilesQueue", '', "ERROR", "red")

    return output


# Dump Loaded DLLs
def dumpDllsQueue(outputDir, memFullPath):
    output = []
    dumpDllsOutput = os.path.join(outputDir, DUMPDLLSoutputDir)

    # Create Output Directory
    if not os.path.isdir(dumpDllsOutput):
        os.mkdir(dumpDllsOutput)

    # Create Command to Dump Loaded DLLs with Volatility3
    cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -o " + dumpDllsOutput + " windows.dlllist.DllList --dump > /dev/null 2>&1"
    data = {'Name': "Dumping DLLs", 'CMD': cmd}
    output.append(data)

    return output


# Dump Processes
def dumpProcessesQueue(outputDir, memFullPath):
    output = []
    dumpProcessOutput = os.path.join(outputDir, DUMPPROCESSESoutputDir)

    # Create Output Directory
    if not os.path.isdir(dumpProcessOutput):
        os.mkdir(dumpProcessOutput)

    # Create Command to Dump Loaded Processes with Volatility3
    cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -o " + dumpProcessOutput + " windows.pslist.PsList --dump > /dev/null 2>&1"
    data = {'Name': "Dumping Processes", 'CMD': cmd}
    output.append(data)

    return output


# Dump Modules
def dumpModulesQueue(outputDir, memFullPath):
    output = []
    dumpModulesOutput = os.path.join(outputDir, DUMPMODULESoutputDir)

    # Create Output Directory
    if not os.path.isdir(dumpModulesOutput):
        os.mkdir(dumpModulesOutput)

    # Create Command to Dump Loaded Modules with Volatility3
    cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -o " + dumpModulesOutput + " windows.modscan.ModScan --dump > /dev/null 2>&1"
    data = {'Name': "Dumping Modules", 'CMD': cmd}
    output.append(data)

    return output


# Dump Registry
def dumpRegistryQueue(outputDir, memFullPath):
    output = []
    dumpRegistryOutput = os.path.join(outputDir, DUMPREGISTRYoutputDir)

    # Create Output Directory
    if not os.path.isdir(dumpRegistryOutput):
        os.mkdir(dumpRegistryOutput)

    # Create Command to Dump Loaded Registry Hives with Volatility3
    cmd = VOL3PATH + " -f " + '\"' + memFullPath + '\"' + " -o " + dumpRegistryOutput + " windows.registry.hivelist.HiveList --dump > /dev/null 2>&1"
    data = {'Name': "Dumping Registry", 'CMD': cmd}
    output.append(data)

    return output


# Plaso Function
def runPlaso(outputDir, memFullPath):
    printLoggingLogic("Running Plaso", False, "INFO")
    cleanUp = ["Worker_", "log2timeline-", "psort-"]
    plasoOutputPath = os.path.join(outputDir, PLASOOUTPUT)

    # Create Output Directory
    if not os.path.isdir(plasoOutputPath):
        os.mkdir(plasoOutputPath)

    # Get Output File Name/Paths
    memFileName = memFullPath.split('/')[len(memFullPath.split('/')) - 1]
    plasoOutputFullPath = os.path.join(plasoOutputPath, memFileName + ".plaso")
    tlnOutputFullPath = os.path.join(plasoOutputPath, memFileName + ".tln")

    # Run Log2Timeline
    cmd = LOG2TIMELINEPATH + " " + plasoOutputFullPath + " " + outputDir + " > /dev/null 2>&1"
    runCMD(cmd, "Log2Timeline")

    # Run Psort on the Output
    cmd = PSORTPATH + " -w " + tlnOutputFullPath + " " + plasoOutputFullPath + " > /dev/null 2>&1"
    runCMD(cmd, "PSORT")

    # Cleanup Left Over Plaso Files
    for file in os.listdir("."):
        if any(item in file for item in cleanUp):
            os.remove(file)


# Get Network IOCs from Output
def getNetIOCs(outputDir):
    netIOCData = []
    vol3OutputPath = os.path.join(outputDir, VOL3outputDir)
    vol3NetScanPath = os.path.join(vol3OutputPath, "windows.netscan.NetScan.csv")

    try:
        # Volatility IP Extraction
        if os.path.isfile(vol3NetScanPath):
            vol3NetScanObj = csv.DictReader(open(vol3NetScanPath, 'r'))
            for row in vol3NetScanObj:
                foreignAddr = row['ForeignAddr']
                if not foreignAddr == '*':
                    if not ipaddress.ip_address(foreignAddr).is_private:
                        data = {"Source": vol3NetScanPath, "Type": "IP Address", "Value": foreignAddr}
                        netIOCData.append(data)
    except Exception as e:
        printLoggingLogic(str(e), False, "ERROR", "red")

    return netIOCData


# Main Function for IOC Collection
def getIOCs(outputDir):
    # Collect Network IOCs
    printLoggingLogic("Collecting Network IOCs", False, "INFO")
    iocs = getNetIOCs(outputDir)

    # Write Output to File
    if iocs:
        iocOutputObj = open(os.path.join(outputDir, IOCOUTPUT), 'w')
        csvWritter = csv.DictWriter(iocOutputObj, fieldnames=iocs[0].keys())
        csvWritter.writeheader()
        for item in iocs:
            csvWritter.writerow(item)


# Run Yara
def runYara(outputDir):
    dumpModulesOutput = os.path.join(outputDir, DUMPMODULESoutputDir)
    dumpProcessOutput = os.path.join(outputDir, DUMPPROCESSESoutputDir)
    dumpDllsOutput = os.path.join(outputDir, DUMPDLLSoutputDir)
    yaraOutput = os.path.join(outputDir, YARAoutputDir)

    # Create Output Directory
    if not os.path.isdir(yaraOutput):
        os.mkdir(yaraOutput)

    # Run Yara Across the Dumped Files
    if os.path.isfile(YARARULESFILE):
        for directory in dumpModulesOutput, dumpProcessOutput, dumpDllsOutput:
            cmd = YARAPATH + " -g -m -s -e --threads=" + str(THREADCOUNT) + " " + YARARULESFILE + " -r " + directory + \
                  " 2> " + os.path.join(yaraOutput, "yara.stderr") + " > " + os.path.join(yaraOutput, "yara.stdout")

            printLoggingLogic("Running Yara Scan on " + directory, False, "INFO")
            runCMD(cmd, "Yara")
    else:
        printLoggingLogic("Cant Find File " + YARARULESFILE, False, "ERROR", 'red')


# Processing Logic
def processing(triageType, memFullPath, outputDir, vol2Profile):
    # Quick Triage Settings
    if triageType == 1:
        threadInput = volatility3Queue(QUICKTRIAGEPLUGINS, memFullPath, outputDir)
        threadInput += bulkExtractorQueue(outputDir, memFullPath)
        threadInput += stringsQueue(memFullPath, outputDir)
        threadPbar(threadInput, "Pre-Processing")

    # Full Triage Settings
    elif triageType == 2:
        threadInput = volatility3Queue((QUICKTRIAGEPLUGINS + FULLTRIAGEPLUGINS), memFullPath, outputDir)
        threadInput += bulkExtractorQueue(outputDir, memFullPath)
        threadInput += stringsQueue(memFullPath, outputDir)
        threadInput += volatility2Queue(VOL2PLUGINS, memFullPath, outputDir, vol2Profile)
        threadInput += evtxtractQueue(outputDir, memFullPath)
        threadInput += dumpRegistryQueue(outputDir, memFullPath)
        threadPbar(threadInput, "Pre-Processing")

        # Extract Certain Files/Directories from DumpFiles Output
        filetypes = ['.evtx', '.pf', '.lnk', '\\ntuser.dat', '\\usrclass.dat', '\\MPDetection-', '\\MPLog-',
                     '\\WebCacheV01.dat', '.hve', '\\current.mdb', '$i30,', '$mft', '$logfile', '$j']
        filepaths = ['\\recent\\automaticdestinations', '\\recent\\customdestinations', '\\windows\\system32\\config',
                     "\\system32\\tasks"]
        threadInput = dumpFilesQueue(outputDir, memFullPath, filetypes, filepaths)
        threadPbar(threadInput, "Dumping Files")

        # Collect IOCs
        getIOCs(outputDir)

        # Run Plaso
        runPlaso(outputDir, memFullPath)

    # Comprehensive Triage Settings
    elif triageType == 3:
        threadInput = volatility3Queue((QUICKTRIAGEPLUGINS + FULLTRIAGEPLUGINS), memFullPath, outputDir)
        threadInput += bulkExtractorQueue(outputDir, memFullPath)
        threadInput += stringsQueue(memFullPath, outputDir)
        threadInput += volatility2Queue(VOL2PLUGINS, memFullPath, outputDir, vol2Profile)
        threadInput += evtxtractQueue(outputDir, memFullPath)
        threadInput += dumpRegistryQueue(outputDir, memFullPath)
        threadInput += dumpDllsQueue(outputDir, memFullPath)
        threadInput += dumpProcessesQueue(outputDir, memFullPath)
        threadInput += dumpModulesQueue(outputDir, memFullPath)
        threadPbar(threadInput, "Pre-Processing")

        # Extract Certain Files/Directories from DumpFiles Output
        filetypes = ['.evtx', '.pf', '.lnk', '\\ntuser.dat', '\\usrclass.dat', '\\MPDetection-', '\\MPLog-',
                     '\\WebCacheV01.dat', '.hve', '\\current.mdb', '$i30,', '$mft', '$logfile', '$j']
        filepaths = ['\\recent\\automaticdestinations', '\\recent\\customdestinations', '\\windows\\system32\\config',
                     "\\system32\\tasks"]
        threadInput = dumpFilesQueue(outputDir, memFullPath, filetypes, filepaths)
        threadPbar(threadInput, "Dumping Files")

        # Collect IOCs
        getIOCs(outputDir)

        # Run Plaso
        runPlaso(outputDir, memFullPath)

        # Run Yara
        runYara(outputDir)


# Main Function
def main():
    # Stats on Script Run Time
    startTime = time.time()

    # Define Argparser for Input
    triageOptions = {1: 'QuickTriage', 2: 'FullTriage', 3: 'ComprehensiveTriage'}
    parser = ArgumentParser(description='winSuperMem is a script to automate processing of a Windows memory images', formatter_class=RawTextHelpFormatter)
    parser.add_argument('-f', '--fullpath=', type=str, help='Full path to memory file', required=True, dest='FullPath')
    parser.add_argument('-o', '--output=', type=str, help='Full path to output directory', required=True, dest='Output')
    parser.add_argument('-p', '--profile=', type=str, help='Volatility2 profile', required=False, dest='Vol2Profile')
    parser.add_argument('-tt', '--triagetype=', help='Triage type: ' + str(triageOptions), type=int,
                        required=True, dest='TriageType')
    args = parser.parse_args()

    # Grab Input Values
    memFullPath = os.path.abspath(args.FullPath)
    outputDir = os.path.abspath(args.Output)
    triageType = args.TriageType
    vol2Profile = args.Vol2Profile

    # Quit if an Invalid Triage Type was Supplied
    if triageType not in triageOptions.keys():
        print(colored("Invalid Value for Triage Type"), 'red')
        quit()

    # Quit if You Can't Find the File
    if not os.path.isfile(memFullPath):
        print(colored("Can't find file: " + memFullPath), "red")
        quit()

    # Create Output Directory
    if not os.path.isdir(outputDir):
        os.mkdir(outputDir)

    # For Logging Output Messages
    logging.basicConfig(filename=os.path.join(outputDir, LOGGINGOUTPUT),
                        format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO,
                        datefmt='%Y-%m-%dT%H:%M:%S')

    # Print Script Header
    printLoggingLogic("**************************", False, "INFO", "blue")
    printLoggingLogic("File Name: " + memFullPath, False, "INFO", "blue")
    printLoggingLogic("Output Directory: " + outputDir, False, "INFO", "blue")
    printLoggingLogic("Triage Type: " + triageOptions[triageType], False, "INFO", "blue")
    printLoggingLogic("Command: " + " ".join(sys.argv), False, "INFO", "blue")
    printLoggingLogic("**************************", False, "INFO", "blue")

    # Start Processing
    processing(triageType, memFullPath, outputDir, vol2Profile)
    executionTime = (time.time() - startTime)
    printLoggingLogic("Finished all processing in " + str(int(executionTime / 60)) + " minutes", False, "INFO", "blue")


main()
