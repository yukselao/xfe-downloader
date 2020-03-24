# xfe-downloader: Covid19 IOCs

Downloads IOCs on https://exchange.xforce.ibmcloud.com/collection/Threat-Actors-Capitalizing-on-COVID-19-f812020e3eddbd09a0294969721643fe and linked collections. Creates QRadar Reference Sets with these contents.

The content can be used for threat hunting with historical investigation. Also the content can be used with IDS/IPS solutions

This tool is not part of official QRadar setup. Should be run on console. Tested on QRadar 7.3.3 community edition.

Edit xfe-downloader.ini file for api key/password definition.

# Installation

Extract files to /root/xfe-downloader

# Usage:

qradar-console# cd /root/xfe-downloader

qradar-console# ./xfe-downloader.py

Demo Video:
https://ibm.box.com/s/r2dwbua7b9xt29g69dfk7o5nakc8voum

