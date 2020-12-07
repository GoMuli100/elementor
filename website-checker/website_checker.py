import requests
import json
import base64
import sqlite3
import datetime
from datetime import timedelta

chunkSize=1

def create_connection():
    conn = sqlite3.connect("localDB")
    query = "create table if not exists sites(site varchar(256), lastCheck datetime, lastResult varchar(10))"
    conn.cursor().execute(query)
    return conn

def getResultsFromApi(site):
    headers = {
        'X-Apikey': '69fb91a5dd64792bbeac56741499875b9faa35ce79ec924bb344e29a625531e7',
    }

    params = (('query', site),)

    response = requests.get('https://www.virustotal.com/api/v3/search', headers=headers, params=params)
    response_dict = (json.loads(response.text))
    print(params)
    results = response_dict["data"][0]["attributes"]["last_analysis_results"]
    statuses = {}
    categories = {}
    for result in results:
        if results[result]["result"] in statuses:
            statuses[results[result]["result"]]+=1
        else:
            statuses[results[result]["result"]]=0

        if results[result]["category"] in categories:
            categories[results[result]["category"]]+=1
        else:
            categories[results[result]["category"]]=0
        
    site_results = {
        "site":site,
        "votes":statuses,
        "categories":categories
        }
    return site_results

def saveResultToDB(conn,newData,newRow):
    if newRow==0:
        query = "update sites set lastCheck=now(), lastResult=? where site=?"
    else:
        query = "insert into sites(lastResult,site,lastCheck) values(?,DATETIME('now'),?)"
    finalResult = "clean"
    if "malicious" in newData["votes"]:
        if newData["votes"]["malicious"]>1:
            finalResult="risk"
    if "suspicious" in newData["votes"]:
        if newData["votes"]["suspicious"]>1:
            finalResult="risk"
    curr = conn.cursor()
    curr.execute(query,(finalResult,newData["site"]))
    conn.commit()
    print(query)

def doSomething(conn,chunk):
    site = chunk[0]
    query = "select lastCheck from sites where site=?"
    curr = conn.cursor()
    curr.execute(query,(site,))
    rows = curr.fetchall()
    if len(rows)==0:
        site_result = getResultsFromApi(site)
        saveResultToDB(conn,site_result,1)
    for row in rows:
        if row[0]<datetime.datetime.now()+timedelta(minutes=-30):
            site_result = getResultsFromApi(site)
            saveResultToDB(conn,site_result,0)

def getUrlsFromFile(conn,filePath):
    iterator = 0
    chunk = []
    with open(filePath) as infile:
        for line in infile:
            chunk.append(line.replace("\n",""))
            iterator+=1
            if iterator==chunkSize:
                doSomething(conn,chunk)
                iterator=0
                chunk=[]
    if iterator>0:
        doSomething(conn,chunk)

conn = create_connection()
getUrlsFromFile(conn,"/Users/muligolan/elementor/website-checker/request1.csv")