# xfe-downloader: Covid19 IOCs

IBM X-force team is regularly updating this report topic (https://exchange.xforce.ibmcloud.com/collection/Threat-Actors-Capitalizing-on-COVID-19-f812020e3eddbd09a0294969721643fe).

Collecting IOCs together with linked collections is not easy operation. The tool extracts latest IOCs from the report and from linked collections also. And imports to Qradar. The reference data includes malicious signatures. The content can be used for threat hunting with historical investigation. Also the content can be used with IDS/IPS solutions.

This tool is not part of official QRadar setup. Should be run on console. Tested on QRadar 7.3.3 community edition.

X-force: Obtaining the API key and password
https://www.ibm.com/support/knowledgecenter/SSHLHV_5.4.0/com.ibm.alps.doc/tasks/alps_obtaining_api_key_password.htm

Edit xfe-downloader.ini file for api key/password definition.

# Installation

Extract files to /root/xfe-downloader:

qradar-console# cd /root/

qradar-console# git clone https://github.com/yukselao/xfe-downloader.git

# Demo Video:

[![Watch demo video](https://img.youtube.com/vi/0aZr8TPCLOU/0.jpg)](https://www.youtube.com/watch?v=0aZr8TPCLOU) 


# Usage:

qradar-console# cd /root/xfe-downloader

qradar-console# ./xfe-downloader.py


