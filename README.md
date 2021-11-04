# Overview

A python script developed to process Windows memory images based on triage type. 

# Requirements
- Python3
- Bulk Extractor
- Volatility2 with Community Plugins
- Volatility3
- Plaso
- Yara

# How to Use
## Quick Triage

`python3 winSuperMem.py -f memdump.mem -o output/ -tt 1`

## Full Triage

`python3 winSuperMem.py -f memdump.mem -o output/ -tt 2`

## Comprehensive Triage

`python3 winSuperMem.py -f memdump.mem -o output/ -tt 3`

# Installation
1. Install Python 3
2. Install Python 2
3. pip3 install -r requirements.txt
4. Install Volatility 3 Framework
5. Install Volatility 2 Framework
6. Download Volatility 2 Community Plugins
7. Install Bulk Extractor
8. Install Plaso
9. Install Yara
10. Install Strings
11. Install EVTxtract

# How to Read the Output
- Output directory structure of comprehensive triage:
    - BEoutputdir - Bulk Extractor output
    - DumpedDllsOutput - Dumped DLLs loaded into processes
    - DumpedFilesOutput - Dumped files in memory
    - DumpedModules - Dumped loaded drivers
    - DumpedProcessOutput - Dumped running processes
    - DumpedRegistry - Dumped loaded registry hives
    - EVTxtract - Extracted data with EVTxtract
    - IOCs.csv - Collected IPs identified in the output data set
    - Logging.log - Logging for the script
    - Plaso - Plaso master timeline
    - Strings - Unicode, Ascii, Big Endian strings output
    - Volatility2 - Volatility2 plugin output 
    - Volatility3 - Volatility3 plugin output
    - Yara - Yara matches
    
# Troubleshooting
There are a number of known bugs, which are outlined in this section.
- Dumping files may not work on Windows images below Windows8. The offset supplied by the volatility3 filescan plugin is sometimes physical and not virtual. There is not a descriptor specifying which is returned either. The current script is expecting virtual only. You can fix this by changing the dumpfiles function from `--virtaddr` to `--physaddr`.
