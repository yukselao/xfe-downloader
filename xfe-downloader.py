#!/usr/bin/python
import requests, base64, json, traceback, os, subprocess, datetime, sys, ConfigParser

'''
Author: Ali Okan Yuksel
e-mail: aliokan.yuksel@ibm.com
Date: 2020-03-24

Description:
Downloads IOCs on https://exchange.xforce.ibmcloud.com/collection/Threat-Actors-Capitalizing-on-COVID-19 and linked collections. Creates QRadar Reference Sets with these contents.

This tool is not part of official QRadar setup. Should be run on console. Tested on QRadar 7.3.3 community edition.

Edit xfe-downloader.ini file for api key/password definition and other settings.


'''

config = ConfigParser.ConfigParser()
config.readfp(open("xfe-downloader.ini","r"))
key=config.get('settings','key')
password=config.get('settings','password')
workdir=config.get('settings','workdir')




token = base64.b64encode(key + ":" + password)
headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}

def getCaseFile(id):
    try:
        global key, password, token, headers
        r=requests.get("https://api.xforce.ibmcloud.com"+id,headers=headers)
        rjson=r.json()
        for link in rjson['links']:
            #print link['caseFileID']
            plog("INFO","Fethcing "+linkp['title']+'...')
            getCaseAttachment("/api/casefiles/"+str(link['caseFileID'])+"/attachments/")
    except Exception as e:
        print e

def getCaseId(id):
    try:
        global key, password, token, headers
        r=requests.get("https://api.xforce.ibmcloud.com"+id,headers=headers)
        rjson=r.json()
        plog('INFO',"Processing "+rjson['title']+'...')
    except Exception as e:
        traceback.print_exc()

def getLinkedCollections(id):
    try:
        global key, password, token, headers
        r=requests.get("https://api.xforce.ibmcloud.com"+id,headers=headers)
        rjson=r.json()
        for link in rjson['linkedcasefiles']:
            #print link['caseFileID']
            plog('INFO',"Processing "+link['title']+'...')
            getCaseAttachment("/api/casefiles/"+str(link['caseFileID'])+"/attachments/")
    except Exception as e:
        traceback.print_exc()

def plog(ltype,lmsg):
        global verbose
        now = datetime.datetime.now()
        nowstr=str(now.year) + "-" + str(now.month).zfill(2) + "-" + str(now.day).zfill(2) + " " + str(now.hour).zfill(2) + ":" + str(now.minute).zfill(2) + ":" + str(now.second).zfill(2)
        lstr=nowstr+" "+ltype+" "+lmsg+"\n"
        #print(lstr)
        os.write(1, bytes(lstr.encode('utf-8')))
def run(cmd,returnexitcode=0):
        returncmd=""
        if returnexitcode == 1:
                returncmd="> /dev/null 2>>/tmp/errors.1; echo $?"
        p = subprocess.Popen(cmd+returncmd, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        if returnexitcode!=1:
            plog("INFO","CommandRun: "+ cmd)
            plog("INFO","CommandOutput: "+output)
        else:
            return output
def getCaseAttachment(id):
    try:
        global key, password, token, headers
        r=requests.get("https://api.xforce.ibmcloud.com"+id,headers=headers)
        rjson=r.json()
        md5file=open('md5','a')
        sha256file=open('sha256','a')
        urlfile=open('url','a')
        for record in rjson['attachments']:
            try:
                if record['report']['type']=="URL":
                    urlfile.write(record['report']['title']+"\n")
                elif record['report']['type']=="MAL":
                    if record['report']['hash_type']=="md5":
                        md5file.write(record['report']['title']+"\n")
                    elif record['report']['hash_type']=="sha256":
                        sha256file.write(record['report']['title']+"\n")
            except:
                pass                        
        md5file.close()
        sha256file.close()
        urlfile.close()                                 
    except Exception as e:
        traceback.print_exc()
def purgecontent():
    run("echo ''>md5",1)
    run("echo ''>sha256",1)
    run("echo ''>url",1)
def main():
    try:
        os.mkdir(workdir)
    except:
        pass
    os.chdir(workdir)
    purgecontent()
    #getCaseFile("/casefiles/f812020e3eddbd09a0294969721643fe")
    getCaseId("/casefiles/f812020e3eddbd09a0294969721643fe")
    getCaseAttachment("/api/casefiles/f812020e3eddbd09a0294969721643fe/attachments/")
    getLinkedCollections("/casefiles/f812020e3eddbd09a0294969721643fe/linkedcasefiles")
    run("wc -l md5 sha256 url")
    os.chdir('/opt/qradar/bin')
    run('./ReferenceDataUtil.sh create custom_xfe_covid19_url SET ALN')
    run('./ReferenceDataUtil.sh create custom_xfe_covid19_md5 SET ALN')
    run('./ReferenceDataUtil.sh create custom_xfe_covid19_sha256 SET ALN')
    os.chdir(workdir)    
    run("sed -i '1 i\data' md5")
    run("sed -i '1 i\data' sha256")
    run("sed -i '1 i\data' url")
    os.chdir('/opt/qradar/bin')    
    run("./ReferenceDataUtil.sh purge custom_xfe_covid19_url")
    run("./ReferenceDataUtil.sh load custom_xfe_covid19_url "+workdir+"/url")
    run("./ReferenceDataUtil.sh purge custom_xfe_covid19_md5")
    run("./ReferenceDataUtil.sh load custom_xfe_covid19_md5 "+workdir+"/md5")
    run("./ReferenceDataUtil.sh purge custom_xfe_covid19_sha256")
    run("./ReferenceDataUtil.sh load custom_xfe_covid19_sha256 "+workdir+"/sha256")    

if __name__ == "__main__":
    main()


