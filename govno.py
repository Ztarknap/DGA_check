import csv
from usp.tree import sitemap_tree_for_homepage



def siteMapCheck(dnsName):
    http_dnsName = 'http://www.'+ dnsName + '/'
    siteTree = sitemap_tree_for_homepage(http_dnsName)
    print(siteTree)
    q = siteTree.all_pages()
    for page in siteTree.all_pages():
        print(page)
        q = 3
    k = 3



def sldLength(dnsName):
    t = len(dnsName.split('.')[-1])
    return t

def flagDGA(dnsName):
    flagDGA = 0
    if (dnsName.split('.')[-1]) in ['study', 'party', 'click','top','gdn','gq','asia','cricket','biz','cf']:
        flagDGA = 1
    return flagDGA

def isFirstDigit(dnsName):
    flagFirstDigit = 0
    if dnsName[0].isdigit():
        flagFirstDigit = 1
    return flagFirstDigit

def consDigRatio(dnsName):
    consDigList = []
    consDigs = 0
    streak = 0
    lastElem = ''
    for elem in dnsName:
        if elem.isdigit() and lastElem.isdigit():
            consDigs = consDigs + 1
            streak = 1
        else: 
            if streak == 1:
                consDigs = consDigs + 1
                streak = 0
        lastElem = elem
    result =  consDigs/len(dnsName)   
    return result

def uniqueCharNum(dnsName):
    dnsName = dnsName.replace('.', '')
    result = len(''.join(set(dnsName)))       
    return result



def extractDataMajestic(filename, delim):
    count=0
    data = []
    reader = csv.reader(open(filename), delimiter=delim)
    for row in reader:
        name = (row[0].split(','))[2]
        data.append(name)
        count=count+1
    
    return data

def extractWhiteList():
    topSites=extractDataMajestic(r'D:\\magisterskaya\\top_sites.txt','\n')
    whitelist = []
    for row in topSites:
        whitelist.append(row)
    return whitelist

def checkWhiteList(dnsName, whitelist):
    if dnsName in whitelist:
        return 1
    else:
        return 0

q = siteMapCheck('nytimes.com')

whitelist = extractWhiteList()
k = checkWhiteList('google.com', whitelist)

k = uniqueCharNum('youtube.ru')

k = isFirstDigit('2afagd.d')
k = isFirstDigit('afagd.d')
k = isFirstDigit('$£afagd.d')
k = isFirstDigit('23afagd.d')

q = flagDGA('google.com')
q = flagDGA('google.biz')
q = flagDGA('google.party.click')
q = flagDGA('google.party.com')
q = flagDGA('google.comq.asia')
q = flagDGA('google.cricket')