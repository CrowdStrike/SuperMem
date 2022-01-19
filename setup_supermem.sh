#!/bin/bash
# This is a helper script to assist with installation of the dependencies of CrowdStrike's SuperMem (https://github.com/CrowdStrike/SuperMem) 
# Written by J Marasinghe
# Tested with Ubuntu 20.04.3 LTS

Copyright 2021 CrowdStrike, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of 
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.

add-apt-repository ppa:gift/stable -y
apt-get update
apt-get install git python3 python2 python3-pip yara unzip zip plaso-tools -y

#Setting up Volatility 2
cd /opt/
wget http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_lin64_standalone.zip
unzip volatility_2.6_lin64_standalone.zip
cd volatility_2.6_lin64_standalone
mv volatility_2.6_lin64_standalone vol.py
cp vol.py /usr/bin/

#Setting up Volatility 3
cd /opt/
git clone --recursive https://github.com/volatilityfoundation/volatility3.git
cd volatility3/
pip3 install -r requirements.txt
python3 setup.py build
python3 setup.py install
mv vol.py vol3.py
cp vol3.py /usr/bin/


#Download Volatility plugins
cd /opt/ 
git clone --recursive https://github.com/volatilityfoundation/community.git

#Installing evtxtract
pip install evtxtract

#Installing Bulk_extractor
cd /opt/
git clone --recursive https://github.com/simsong/bulk_extractor.git
echo -ne '\n' | bash bulk_extractor/etc/CONFIGURE_UBUNTU20LTS.bash
cd bulk_extractor/
./configure
make
make install

#Downloading YARA rules 
cd /opt/
git clone --recursive https://github.com/Yara-Rules/rules.git

#Setting up SuperMem
git clone https://github.com/blueteam0ps/SuperMem.git
cd SuperMem
pip3 install -r requirements.txt
