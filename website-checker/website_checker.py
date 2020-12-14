import requests
import json
import base64
import sqlite3
import datetime
from datetime import timedelta

chunkSize=1
riskStatuses = ('malicious','phishing','malware')

def create_connection():
    conn = sqlite3.connect("localDB",
        detect_types=sqlite3.PARSE_DECLTYPES |
        sqlite3.PARSE_COLNAMES)
    query = "create table if not exists sites(site varchar(256) primary key ON CONFLICT REPLACE, lastCheck datetime, lastResult varchar(10))"
    conn.cursor().execute(query)
    query = "create table if not exists siteCategories(site varchar(256), category varchar(256), categoryCounter int)"
    conn.cursor().execute(query)
    query = "create table if not exists siteVotes(site varchar(256), vote varchar(256), voteCounter int)"
    conn.cursor().execute(query)
    return conn

def getResultsFromApi(site):
    headers = {
        'X-Apikey': '69fb91a5dd64792bbeac56741499875b9faa35ce79ec924bb344e29a625531e7',
    }

    params = (('query', site),)

    response = requests.get('https://www.virustotal.com/api/v3/search', headers=headers, params=params)
    response_dict = (json.loads(response.text))
    results = response_dict["data"][0]["attributes"]["last_analysis_results"]
    statuses = {}
    categories = {}
    for result in results:
        if results[result]["result"] in statuses:
            statuses[results[result]["result"]]+=1
        else:
            statuses[results[result]["result"]]=0

    results = response_dict["data"][0]["attributes"]["categories"]
    for result in results:
        if results[result] in categories:
            categories[results[result]]+=1
        else:
            categories[results[result]]=1
        
    site_results = {
        "site":site,
        "votes":statuses,
        "categories":categories
        }
    return site_results

def saveResultToDB(conn,newData):
    votes = ""
    categories = ""
    query = "insert into sites(lastResult,site,lastCheck) \
            values(?,?,DATETIME('now'))"
    finalResult = "safe"
    for vote in newData["votes"]:
        if votes=="":
            votes = "('"+newData["site"]+"','"+vote+"',"+str(newData["votes"][vote])+")"
        else:
            votes += ",('"+newData["site"]+"','"+vote+"',"+str(newData["votes"][vote])+")"
        if vote in riskStatuses and newData["votes"][vote]>1:
            finalResult="risk"

    for category in newData["categories"]:
        if categories=="":
            categories = "('"+newData["site"]+"','"+category+"',"+str(newData["categories"][category])+")"
        else:
            categories += ",('"+newData["site"]+"','"+category+"',"+str(newData["categories"][category])+")"

    curr = conn.cursor()
    curr.execute(query,(finalResult,newData["site"]))
    query = "delete from siteCategories where site=?"
    curr.execute(query,(newData["site"],))
    query = query = "insert into siteCategories values "+categories
    curr.execute(query)
    query = "delete from siteVotes where site=?"
    curr.execute(query,(newData["site"],))
    query = "insert into siteVotes values "+votes
    curr.execute(query)
    conn.commit()

def processChunk(conn,chunk):
    site = chunk[0]
    query = "select lastCheck from sites where site=?"
    curr = conn.cursor()
    curr.execute(query,(site,))
    rows = curr.fetchall()
    if len(rows)==0:
        site_result = getResultsFromApi(site)
        saveResultToDB(conn,site_result)
    for row in rows:
        if datetime.datetime.strptime(row[0],"%Y-%m-%d %H:%M:%S")<datetime.datetime.utcnow()-timedelta(minutes=1):
            site_result = getResultsFromApi(site)
            saveResultToDB(conn,site_result)

def getUrlsFromFile(conn,filePath):
    iterator = 0
    chunk = []
    with open(filePath) as infile:
        for line in infile:
            chunk.append(line.replace("\n",""))
            iterator+=1
            if iterator==chunkSize:
                processChunk(conn,chunk)
                iterator=0
                chunk=[]
    if iterator>0:
        processChunk(conn,chunk)

conn = create_connection()
getUrlsFromFile(conn,"/Users/muligolan/elementor/website-checker/request1.csv")

#printing results, not part of the solution
query = "select * from sites"
crr = conn.cursor()
for r in crr.execute(query):
    print(r)
query = "select * from siteCategories"
crr = conn.cursor()
for r in crr.execute(query):
    print(r)
query = "select * from siteVotes"
crr = conn.cursor()
for r in crr.execute(query):
    print(r)