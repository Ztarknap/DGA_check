import numpy as np
import collections
import math
import csv
import sys
import sqlite3
import time
import whois
import json
import hashlib
import wordsegment
from wordsegment import load, segment, clean
import socket
#import datetime
import subprocess
import smtplib
import statistics
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import cross_val_score, train_test_split, RepeatedKFold, GridSearchCV
from sklearn.metrics import confusion_matrix, f1_score   

from joblib import dump, load
from sklearn import tree, preprocessing, svm
from collections import Counter
from datetime import datetime
from sklearn.model_selection import StratifiedKFold
from Levenshtein import distance
#from ip2geotools.databases.noncommercial import DbIpCity
from math import log, e
from itertools import tee, islice, chain

#avg_dga = 2.3809
avg_sum = 0.1515
np.set_printoptions(precision=6)

wordsegment.load()

start_time = time.time()

API_KEY = 'f6efc17a887ad7245fcff3458d45f257e290ceaa9d96f437920afad7cc3cb2ed'

def Optimize():
    param_grid = {}
    datasetLegit=featuresFromFile('./calculatedParametersLegit.txt', '\n')
    datasetGenerated=featuresFromFile('./calculatedParametersGenerated.txt','\n')
    
    y=[]

    x = np.concatenate((datasetLegit, datasetGenerated), axis = 0)
    

    for dnsName in datasetGenerated:
        y.append('DGA')

    for dnsName in datasetLegit:
        y.append('NORMAL')

   

    y = np.array(y).reshape(np.array(y).shape[0],-1)
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 1)


    
    if sys.argv[2]=='-RF':
        print('RandomForest initialized')
        n_estimators = [int(x) for x in np.linspace(start = 200, stop = 2000, num = 10)]
        max_features = ['auto', 'sqrt']
        min_samples_leaf = [1, 2, 4]
        param_grid = {'n_estimators': n_estimators,
                'max_features': max_features,
                'min_samples_leaf': min_samples_leaf}
        clf = RandomForestClassifier(random_state = 1)
        
    if sys.argv[2]=='-CART':
        clf = tree.DecisionTreeClassifier()
        max_depth = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        param_grid = { 'max_depth': max_depth}
        print('CART initialized')
        #https://projector-video-pdf-converter.datacamp.com/6280/chapter5.pdf
        #https://sci-hub.im/10.1109/AIKE.2018.00038
        #10 = 9, 5 = 9, 2 = 10
    
    if sys.argv[2]=='-SVC':
        clf = svm.SVC()
        gammas = [0.1, 1, 10, 100]
        cs = [0.1, 1, 10, 100, 1000]
        kernels = ['linear', 'rbf', 'poly']
        param_grid = { 'gamma' : gammas, 
                'C' : cs,
                'kernel': kernels}
        print('SVC initialized')
        #https://medium.com/all-things-ai/in-depth-parameter-tuning-for-svc-758215394769

   
 
    np.random.set_state = 1
    q = clf.get_params().keys()
    grid_search = GridSearchCV(estimator = clf, param_grid = param_grid, cv = 10, n_jobs = -1, verbose = 2 )
    grid_search.fit(x_train, y_train)
    bestParams = grid_search.best_params_
    print("Execution time")
    print("--- %s seconds ---" % (time.time() - start_time))
    print(bestParams)
    k = 3


def dumpParameters():
    datasetLegit=extractData('D:\\magisterskaya\\LegitTrainSet.php', '\n')
    datasetGenerated=extractData('D:\\magisterskaya\\GeneratedTrainSet.txt',',')
    x1=[]
    x2=[]
    

    for  prevdnsName, dnsName in previous(datasetLegit):
        x1.append(calcParam(dnsName, prevdnsName))
    
    for prevdnsName, dnsName in previous(datasetGenerated):
        x2.append(calcParam(dnsName, prevdnsName))
    x1 = np.array(x1).reshape(np.array(x1).shape[0],-1)
    x2 = np.array(x2).reshape(np.array(x2).shape[0],-1)
    x1.tofile('./calculatedParametersLegitTrain25000.txt',sep = "\n")
    x2.tofile('./calculatedParametersGeneratedTrain25000.txt',sep = "\n")
    
    
def featuresFromFile(filename, delim):
    x = extractData(filename, delim)
    x = np.array(x).reshape(int(np.array(x).shape[0]/13),13)
    xFloat = x.astype(dtype = "float64")
    return xFloat





def checkDate(whoisdate):
    
    print(type(whoisdate))
    try:
        whoisdateLen = len(whoisdate)
    except TypeError:
        if (type(whoisdate)=='list'):
            k = 2
        return whoisdate
    
    return whoisdate[0]

def entropyCalc(dnsName):

     
    prob = [ float(dnsName.count(c)) / len(dnsName) for c in dict.fromkeys(list(dnsName)) ]

    
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

    return entropy



def sldLength(dnsName):
    mas = dnsName.split('.')[-2]
    t = len(mas)
    return t

def flagDGA(dnsName):
    flagDGA = 0
    if (dnsName.split('.')[-1]) in ['study', 'party', 'click','top','gdn','gq','asia','cricket','biz','cf']:
        flagDGA = 1
    return flagDGA

def isFirstDigit(dnsName):
    dnsName = dnsName.split('.')[-2]
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
    if streak == 1:
        consDigs = consDigs + 1
    result =  consDigs/len(dnsName)   
    return result

def uniqueCharNum(dnsName):
    dnsName = dnsName.replace('.', '')
    result = len(''.join(set(dnsName)))       
    return result

def repCharRatio(dnsName):
    repeatedCounter = 0
    freq = collections.Counter(dnsName)
    for i in freq:
        if freq[i] > 1:
            repeatedCounter = repeatedCounter + 1  

    result = repeatedCounter/uniqueCharNum(dnsName)  
    return result


def consonantSeq(dnsName):
    dnsName = dnsName.split('.')[-2]
    longest_cons_seq = 0
    consSeq = 0
    streak = 0
    lastChFlag = 0
    for ch in dnsName:
        if (ch.isalpha() and 
        ch != 'a' and ch != 'e' and ch != 'i' and ch != 'o' and ch != 'u' and 
        ch != 'A' and ch != 'E' and ch != 'I' and ch != 'O' and ch != 'U' and
        lastChFlag == 1):

            consSeq = consSeq + 1
            streak = 1
            lastChFlag = 1
        elif (ch.isalpha() and 
        ch != 'a' and ch != 'e' and ch != 'i' and ch != 'o' and ch != 'u' and 
        ch != 'A' and ch != 'E' and ch != 'I' and ch != 'O' and ch != 'U' and
        lastChFlag == 0):
            lastChFlag = 1
            streak = 0
            consSeq = 0
        else: 
            lastChFlag = 0
            if streak == 1:
                consSeq = consSeq + 1
                if consSeq > longest_cons_seq:
                    longest_cons_seq = consSeq
                streak = 0
                lastChFlag = 0
            consSeq = 0
        if consSeq > longest_cons_seq:
            longest_cons_seq = consSeq
    if lastChFlag == 1 and streak == 1 and consSeq == longest_cons_seq:
        longest_cons_seq = longest_cons_seq + 1
    result =  longest_cons_seq  
    return result


def vTcRatioCalc(dnsName):
    vowels = 0
    consonants = 0
    for ch in dnsName:
        if (ch.isalpha()):
            if( ch == 'a' or ch == 'e' or ch == 'i' or ch == 'o' or ch == 'u' or ch == 'A' or ch == 'E' or ch == 'I' or ch == 'O' or ch == 'U'):
                vowels = vowels + 1
            else:
                consonants = consonants + 1
    if consonants == 0:
        ratio = 0
    else:
        ratio = vowels/consonants
    return ratio

def whoisLookup(dnsName):
    
    whoisFeatures=[]
    try:
        whoisInfo = whois.whois(dnsName)
    except whois.parser.PywhoisError:
        return ['Error, domain is unavaible', 'Error, domain is unavaible', 'Error, domain is unavaible', 'Error, domain is unavaible']
    
    if whoisInfo.text[0 : 9] == 'NOT FOUND' or whoisInfo.text =='' or len(dnsName.split('.')) == 1:
         return ['No info', 'No info', 'No info', 'No info']
    else:
       

        if whoisInfo.registrar is None:
            whoisFeatures.append('No info')
        else:
            whoisFeatures.append(whoisInfo.registrar)
        if whoisInfo.creation_date is None:
            whoisFeatures.append('No info')
        else:
            whoisFeatures.append(whoisInfo.creation_date)
        if whoisInfo.expiration_date is None:
            whoisFeatures.append('No info')
        else:
            whoisFeatures.append(whoisInfo.expiration_date)
        if whoisInfo.org is None:
            whoisFeatures.append('No info')
        else:
            whoisFeatures.append(whoisInfo.org)  
   
    return whoisFeatures
            
  
def sizeofList(lists):
    size=0
    for str1 in lists:
        size = size + len(str1)
    return size
        
def precisDBcalc():
    con = sqlite3.connect("./databases/passDNS.db")
    cursor = con.cursor()
    cursor.execute("""SELECT DISTINCT query FROM dns""")
    dnsNames = [row for row in cursor.fetchall()]
    TotalNumber = len(dnsNames)
    cursor.execute("""SELECT DISTINCT query FROM suspicious WHERE querytype = ? """, ('Malicious'))
    dnsNames = [row for row in cursor.fetchall()] 
    
    TruePositiveNum = len(dnsNames)
    cursor.execute("""SELECT DISTINCT query FROM suspicious WHERE querytype = ? """, ('Benign'))
    dnsNames = [row for row in cursor.fetchall()] 
    
    FalsePositiveNum = len(dnsNames) 
    TrueNegativeNum = TotalNumber - (TruePositiveNum + FalsePostivieNum)
    
    precision = (TrueNegativeNum + TruePositiveNum)/TotalNumber
   
    con.close()
    print (precision)
    

def help():
    print('???????????? ??????????????????')
    print('-d ?????? ???????????????? ?? ??????????')
    print('-l ?????? ???????????????? ?? ????????????????')
    print('-f ?????? DGA ???????????????????? ?? ???????????????????? ???????????????????? ????????????????')
    print('-optimize ?????? ??????????????????????')
    print('???????????? ??????????????????')
    print('-RF ?????? ???????????? RandomForest')
    print('-CART ?????? ???????????? CART')
    print('-SVC ?????? ???????????? SVC')
    
   
def calcSTD(conf_matrix_list_of_arrays):
    TP = []
    FN = []
    FP = []
    TN = []
    for conf_matrix in conf_matrix_list_of_arrays:
        TP.append(conf_matrix[0][0])
        FN.append(conf_matrix[0][1])
        FP.append(conf_matrix[1][0])
        TN.append(conf_matrix[1][1])
    TPstdev = statistics.stdev(TP)
    FNstdev = statistics.stdev(FN)
    FPstdev = statistics.stdev(FP)
    TNstdev = statistics.stdev(TN)
    print('SKO:')
    print(str(TPstdev) + '  ' + str(FNstdev))
    print(str(FPstdev) + '  ' + str(TNstdev))
    print('percentSKO:')
    print(str((TPstdev/4000)*100) + '  ' + str((FNstdev/4000)*100))
    print(str((FPstdev/4000)*100) + '  ' + str((TNstdev/4000)*100))
    q = 3



def timeOfPrediction(clf, dnsName, prevdnsName):
    features = calcParam(dnsName, prevdnsName)
    featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
    exec_time_sum = 0
    for i in range(10):
        single_time = time.time()
        clf.predict(featuresNormalized)
        exec_time_sum = exec_time_sum + (time.time() - single_time)
    exec_time = exec_time_sum/10

    print("Single prediction Execution time --- %s seconds ---" % (exec_time))

    


def learnDump():
    
    datasetLegit=featuresFromFile('./calculatedParametersLegitTrain25000.txt', '\n')
    datasetGenerated=featuresFromFile('./calculatedParametersGeneratedTrain25000.txt','\n')
  
    
    y=[]

    x = np.concatenate((datasetGenerated, datasetLegit), axis = 0)
    

    for dnsName in datasetGenerated:
        y.append('DGA')

    for dnsName in datasetLegit:
        y.append('NORMAL')

    
    datasetLegitTest=featuresFromFile('./calculatedParametersLegitTest25000.txt', '\n')
    datasetGeneratedTest=featuresFromFile('./calculatedParametersGeneratedTest25000.txt','\n')
  
    
    y_test=[]

    x_test = np.concatenate((datasetGeneratedTest, datasetLegitTest), axis = 0)
    

    for dnsName in datasetGeneratedTest:
        y_test.append('DGA')

    for dnsName in datasetLegitTest:
        y_test.append('NORMAL')



    if sys.argv[2]=='-RF':
        print('RandomForest initialized')
        #best:
        #clf = RandomForestClassifier(random_state = 1, max_features = 'auto', min_samples_leaf = 4, n_estimators = 1200)
        clf = RandomForestClassifier(random_state = 1)
        
    if sys.argv[2]=='-CART':
        #clf = tree.DecisionTreeClassifier(max_depth = 10)
        clf = tree.DecisionTreeClassifier()
        print('CART initialized')
    
    if sys.argv[2]=='-SVC':
        clf = svm.SVC(C = 1000, gamma = 100, kernel = 'rbf')
        #clf = svm.SVC()
        print('SVC initialized')
    #a = [100,10,100,10,100,10,100,10,100,10]
    #b = [55,55,55,55,55,55,55,55,55,55]
    #q1 = statistics.stdev(a)
    #q2 = statistics.stdev(b)
    #q3 = np.std(a)
   
    
    #y = np.array(y).reshape(np.array(y).shape[0],-1)
   
    #cv = StratifiedKFold(n_splits = 10, shuffle = True,  random_state = 1)
    clf.fit(x,y)
   
    #for train_index, test_index in cv.split(x,y):
        #x_train, x_test = x[train_index], x[test_index]
        #y_train, y_test = y[train_index], y[test_index]
        #clf.fit(x_train, y_train)
        #conf_matrix = confusion_matrix(y_test, clf.predict(x_test), labels = ['NORMAL', 'DGA'])
        #conf_matrix_list_of_arrays.append(conf_matrix)
    
    #mean_of_conf_matrix_arrays = np.mean(conf_matrix_list_of_arrays, axis = 0)

    conf_matrix = confusion_matrix(y_test, clf.predict(x_test), labels = ['NORMAL', 'DGA'])



    
    #timeOfPrediction(clf, 'yandex.ru', 'vk.com')
    

    #conf_matrix_list_of_arrays = []
    #for val_train_index, val_test_index in cv.split(x,y):
        
        #val_x_train, val_x_test = x_train[val_train_index], x_train[val_test_index]
        #val_y_train, val_y_test = y_train[val_train_index], y_train[val_test_index]
        #clf.fit(val_x_train, val_y_train)
        #predict_mas = clf.predict(val_x_test) #????????????????
        #conf_matrix = confusion_matrix(val_y_test, clf.predict(val_x_test), labels = ['DGA', 'NORMAL'])
        #conf_matrix_list_of_arrays.append(conf_matrix)   
    #mean_pf_conf_matrix = np.mean(conf_matrix)
    #mean_of_conf_matrix_arrays = np.mean(conf_matrix_list_of_arrays, axis = 0)
    #percent_mean_of_conf_matrix_arrays = mean_of_conf_matrix_arrays.copy()
    #percent_mean_of_conf_matrix_arrays[0][0] = (percent_mean_of_conf_matrix_arrays[0][0]/4000)*100
    #percent_mean_of_conf_matrix_arrays[0][1] = (percent_mean_of_conf_matrix_arrays[0][1]/4000)*100
    #percent_mean_of_conf_matrix_arrays[1][0] = (percent_mean_of_conf_matrix_arrays[1][0]/4000)*100
    #percent_mean_of_conf_matrix_arrays[1][1] = (percent_mean_of_conf_matrix_arrays[1][1]/4000)*100

    percent_mean_of_conf_matrix_arrays = conf_matrix.copy()
    percent_mean_of_conf_matrix_arrays[0][0] = (percent_mean_of_conf_matrix_arrays[0][0]/10000)*100
    percent_mean_of_conf_matrix_arrays[0][1] = (percent_mean_of_conf_matrix_arrays[0][1]/10000)*100
    percent_mean_of_conf_matrix_arrays[1][0] = (percent_mean_of_conf_matrix_arrays[1][0]/10000)*100
    percent_mean_of_conf_matrix_arrays[1][1] = (percent_mean_of_conf_matrix_arrays[1][1]/10000)*100


    TP = percent_mean_of_conf_matrix_arrays[0][0]
    FN = percent_mean_of_conf_matrix_arrays[0][1]
    FP = percent_mean_of_conf_matrix_arrays[1][0]
    TN = percent_mean_of_conf_matrix_arrays[1][1]
   # 
    accuracy = (TP + TN)/(TP+TN+FP+FN)
    precision = TP/(TP+FP)
    recall = TP/(TP+FN) 
    Fscore = 2*(precision*recall)/(precision+recall)
    
    
    
    #std_of_conf_matrix_arrays = np.std(conf_matrix_list_of_arrays, axis = 0)
    #conf_matrix = confusion_matrix(y_test, clf.predict(x_test), labels = ['DGA', 'NORMAL'])
    #print(mean_pf_conf_matrix)
    dump(clf, dumpName)    
    #Q = calcSTD(conf_matrix_list_of_arrays)
    print('Execution time ')
    print("--- %s seconds ---" % (time.time() - start_time))
    q = 5

def NewTest():

    correctPredictions=0
    correctPredictionsLegit=0
    correctPredictionsDGA=0
    LegitProb = []
    GeneratedProb = []
    LegitIndicators = []
    GeneratedIndicators = []
    GeneratedPoints = []
    LegitPoints = []
    GeneratedPointsCurrent = []
    LegitPointsCurrent = []
    LegitSumPoints = []
    GeneratedSumPoints = []
    GeneratedTestSet=extractData(r'D:\\projects\\diploma\\test\\GeneratedTestSet100.txt',',')
    LegitTestSet=extractData(r'D:\\projects\\diploma\\test\\LegitTestSet100.php','\n')
    #con = sqlite3.connect("./databases/passDNS.db")
    #cursor = con.cursor()
    #cursor.execute("""SELECT query FROM dns""")
   
    #dbDNS = [row[0] for row in cursor.fetchall()]
   
   # con.close()
    #LegitTestSet=dbDNS
    
    clf = load(dumpName)
    print(clf.classes_)
    #for prevdnsName, dnsName in previous(LegitTestSet):
        #if prevdnsName == dnsName:
            #featuresNormalized = featuresNormalizedLast
        #else:
            #features = calcParam(dnsName, prevdnsName)
            #featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
            #featuresNormalizedLast = featuresNormalized
    
    
    #LegitIndicators = extractData(r'D:\\projects\\diploma\\test\\LegitIndicatorsDump.txt', "\n")
    #LegitIndicators = np.array(LegitIndicatorsPre).reshape(int(np.array(LegitIndicators).shape[0]/4),4)
    
    
    for dnsName in LegitTestSet:
        features = calcParam(dnsName, 'dummy')
        featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
        #featuresNormalizedLast = featuresNormalized  
        LegitProbCurrent = clf.predict_proba(featuresNormalized)
        LegitProb.append(LegitProbCurrent)
        LegitIndicatorsCurrent = threatEvaluateOnlyAPI(dnsName)
        LegitIndicators.append(LegitIndicatorsCurrent)
        

        
    #for iterator in len(LegitIndicators):
        for indicator in LegitIndicatorsCurrent:
            LegitPointsCurrent.append(indicator * LegitProbCurrent[0][0]) 
        points = sum(LegitPointsCurrent)
        if (points <= avg_sum):
                correctPredictionsLegit=correctPredictionsLegit+1
                correctPredictions=correctPredictions+1    
        LegitPoints.append(LegitPointsCurrent)
        LegitPointsCurrent = []
        LegitProbCurrent = []
    
    #LegitIndicators = np.array(LegitIndicators).reshape(np.array(LegitIndicators).shape[0],-1)
    #LegitIndicators.tofile(r'D:\\projects\\diploma\\test\\LegitIndicatorsDump.txt',sep = "\n")

    for el in LegitPoints:
        LegitSumPoints.append(sum(el))
    
    print('Legit:')
    #GeneratedPointsTest.copy(GeneratedPoints)
    print('sum:')
    print(np.sum(LegitPoints, 0))
    print('avg:')
    print(sum(LegitSumPoints)/len(LegitSumPoints))
    
    

    #LegitPoints = np.array(LegitPoints).reshape(np.array(LegitPoints).shape[0],-1)
    #LegitPoints.tofile(r'D:\\projects\\diploma\\test\\LegitPointsDump.txt',sep = "\n")

    for dnsName in GeneratedTestSet:
        features = calcParam(dnsName, 'dummy')
        featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
        #featuresNormalizedLast = featuresNormalized
        GeneratedProbCurrent = clf.predict_proba(featuresNormalized)  
        GeneratedProb.append(GeneratedProbCurrent)

        GeneratedIndicatorsCurrent = threatEvaluateOnlyAPI(dnsName)
        GeneratedIndicators.append(GeneratedIndicatorsCurrent)


        
        
        for indicator in GeneratedIndicatorsCurrent:
            
            GeneratedPointsCurrent.append(indicator * GeneratedProbCurrent[0][0]) 
        points = sum(GeneratedPointsCurrent)

        if (points >= avg_sum):
            correctPredictionsDGA=correctPredictionsDGA+1
            correctPredictions=correctPredictions+1
        GeneratedPoints.append(GeneratedPointsCurrent)
        GeneratedPointsCurrent = []
        GeneratedProbCurrent = []

    #GeneratedIndicators = np.array(GeneratedIndicators).reshape(np.array(GeneratedIndicators).shape[0],-1)
    #GeneratedIndicators.tofile(r'D:\\projects\\diploma\\test\\GeneratedIndicatorsDump.txt',sep = "\n")

    for el in GeneratedPoints:
        GeneratedSumPoints.append(sum(el))
    
    print('Generated:')
    #GeneratedPointsTest.copy(GeneratedPoints)
    print('sum:')
    print(np.sum(GeneratedPoints, 0))
    print('avg:')
    print(sum(GeneratedSumPoints)/len(GeneratedSumPoints))
    
    #GeneratedPoints = np.array(GeneratedPoints).reshape(np.array(GeneratedPoints).shape[0],-1)
    #GeneratedPoints.tofile(r'D:\\projects\\diploma\\test\\GeneratedPointsDump.txt',sep = "\n")



    
    
        
    q = 3

   #for prevdnsName, dnsName in previous(GeneratedTestSet):
        #if prevdnsName == dnsName:
            #featuresNormalized = featuresNormalizedLast
        #else:
            #features = calcParam(dnsName, prevdnsName)
            #featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
            #featuresNormalizedLast = featuresNormalized

        #if (clf.predict(featuresNormalized)) == ['DGA']:
            #correctPredictionsDGA=correctPredictionsDGA+1
            #correctPredictions=correctPredictions+1 
   
    #correctPercentLegit=correctPredictionsLegit/(len(LegitTestSet))
    #correctPercentDGA=correctPredictionsDGA/(len(GeneratedTestSet))    
    #correctPercent=correctPredictions/(len(LegitTestSet+GeneratedTestSet))
       
    print("NORMAL:")
    #print(correctPercentLegit)
    print("DGA:")
    #print(correctPercentDGA)
    print("OVERALL:")

   # print(correctPercent)
    print('Execution time ')
    print("--- %s seconds ---" % (time.time() - start_time))

def loadTest():
    
    correctPredictions=0
    correctPredictionsLegit=0
    correctPredictionsDGA=0
    LegitProb = []
    GeneratedProb = []
    LegitIndicators = []
    GeneratedIndicators = []
    GeneratedPoints = []
    LegitPoints = []
    GeneratedPointsCurrent = []
    LegitPointsCurrent = []
    LegitSumPoints = []
    GeneratedSumPoints = []
    GeneratedTestSet=extractData(r'./GeneratedTestSet.txt',',')
    LegitTestSet=extractData(r'./LegitTestSet.txt',',')
    #con = sqlite3.connect("./databases/passDNS.db")
    #cursor = con.cursor()
    #cursor.execute("""SELECT query FROM dns""")
   
    #dbDNS = [row[0] for row in cursor.fetchall()]
   
   # con.close()
    #LegitTestSet=dbDNS
    
    clf = load(dumpName)
    print(clf.classes_)
    #for prevdnsName, dnsName in previous(LegitTestSet):
        #if prevdnsName == dnsName:
            #featuresNormalized = featuresNormalizedLast
        #else:
            #features = calcParam(dnsName, prevdnsName)
            #featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
            #featuresNormalizedLast = featuresNormalized
    
    
    #LegitIndicators = extractData(r'D:\\projects\\diploma\\test\\LegitIndicatorsDump.txt', "\n")
    #LegitIndicators = np.array(LegitIndicatorsPre).reshape(int(np.array(LegitIndicators).shape[0]/4),4)
    
    
    for dnsName in LegitTestSet:
        features = calcParam(dnsName, 'dummy')
        featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
        #featuresNormalizedLast = featuresNormalized  
        #LegitProbCurrent = clf.predict_proba(featuresNormalized)
        #LegitProb.append(LegitProbCurrent)
        #LegitIndicatorsCurrent = threatEvaluateOnlyAPI(dnsName)
        #LegitIndicators.append(LegitIndicatorsCurrent)
        if (clf.predict(featuresNormalized)) == ['NORMAL']:
            correctPredictionsLegit=correctPredictionsLegit+1
            correctPredictions=correctPredictions+1


        
    #for iterator in len(LegitIndicators):
        #for indicator in LegitIndicatorsCurrent:
            #LegitPointsCurrent.append(indicator * LegitProbCurrent[0][0]) 
            
        #LegitPoints.append(LegitPointsCurrent)
        #LegitPointsCurrent = []
        #LegitProbCurrent = []
    
    #LegitIndicators = np.array(LegitIndicators).reshape(np.array(LegitIndicators).shape[0],-1)
    #LegitIndicators.tofile(r'D:\\projects\\diploma\\test\\LegitIndicatorsDump.txt',sep = "\n")

    #for el in LegitPoints:
        #LegitSumPoints.append(sum(el))
    
    print('Legit:')
    #GeneratedPointsTest.copy(GeneratedPoints)
    print('sum:')
    #print(np.sum(LegitPoints, 0))
    print('avg:')
    #print(sum(LegitSumPoints)/len(LegitSumPoints))
    
    

    #LegitPoints = np.array(LegitPoints).reshape(np.array(LegitPoints).shape[0],-1)
    #LegitPoints.tofile(r'D:\\projects\\diploma\\test\\LegitPointsDump.txt',sep = "\n")

    for dnsName in GeneratedTestSet:
        features = calcParam(dnsName, 'dummy')
        featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
        #featuresNormalizedLast = featuresNormalized
        #GeneratedProbCurrent = clf.predict_proba(featuresNormalized)  
        #GeneratedProb.append(GeneratedProbCurrent)
        if (clf.predict(featuresNormalized)) == ['DGA']:
            correctPredictionsDGA=correctPredictionsDGA+1
            correctPredictions=correctPredictions+1

        #GeneratedIndicatorsCurrent = threatEvaluateOnlyAPI(dnsName)
        #GeneratedIndicators.append(GeneratedIndicatorsCurrent)


        
        
        #for indicator in GeneratedIndicatorsCurrent:
            #GeneratedPointsCurrent.append(indicator * GeneratedProbCurrent[0][0]) 

        #GeneratedPoints.append(GeneratedPointsCurrent)
        #GeneratedPointsCurrent = []
        #GeneratedProbCurrent = []

    #GeneratedIndicators = np.array(GeneratedIndicators).reshape(np.array(GeneratedIndicators).shape[0],-1)
    #GeneratedIndicators.tofile(r'D:\\projects\\diploma\\test\\GeneratedIndicatorsDump.txt',sep = "\n")

    #for el in GeneratedPoints:
        #GeneratedSumPoints.append(sum(el))
    
    print('Generated:')
    #GeneratedPointsTest.copy(GeneratedPoints)
    print('sum:')
    #print(np.sum(GeneratedPoints, 0))
    print('avg:')
    #print(sum(GeneratedSumPoints)/len(GeneratedSumPoints))
    
    #GeneratedPoints = np.array(GeneratedPoints).reshape(np.array(GeneratedPoints).shape[0],-1)
    #GeneratedPoints.tofile(r'D:\\projects\\diploma\\test\\GeneratedPointsDump.txt',sep = "\n")



    
    
        
    q = 3

   #for prevdnsName, dnsName in previous(GeneratedTestSet):
        #if prevdnsName == dnsName:
            #featuresNormalized = featuresNormalizedLast
        #else:
            #features = calcParam(dnsName, prevdnsName)
            #featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
            #featuresNormalizedLast = featuresNormalized

        #if (clf.predict(featuresNormalized)) == ['DGA']:
            #correctPredictionsDGA=correctPredictionsDGA+1
            #correctPredictions=correctPredictions+1 
   
    #correctPercentLegit=correctPredictionsLegit/(len(LegitTestSet))
    #correctPercentDGA=correctPredictionsDGA/(len(GeneratedTestSet))    
    #correctPercent=correctPredictions/(len(LegitTestSet+GeneratedTestSet))
       
    print("NORMAL:")
    #print(correctPercentLegit)
    print("DGA:")
    #print(correctPercentDGA)
    print("OVERALL:")

   # print(correctPercent)
    print('Execution time ')
    print("--- %s seconds ---" % (time.time() - start_time))



def wordCalc(dnsNamePre):
   
    wordLen=0
    
    dnsName = dnsNamePre.replace('www.','')
    dnsName = dnsName.replace('-', '.')
    dnsName = dnsName.split('.')
    for part in dnsName:
        segmentedName = wordsegment.segment(part)
        for word in segmentedName:
            try:
                if wordsegment.UNIGRAMS[word] > 0:
                    wordLen = wordLen + len(word)
            except Exception:
                continue
        
    MeaningfulWordRatio=wordLen/sizeofList(dnsName)
    return MeaningfulWordRatio 
    

def LMSlength(dnsNamePre):
    maxLength=0
    dnsName = dnsNamePre.replace('www.','')
    dnsName = dnsName.replace('-', '.')
    dnsName = dnsName.split('.')
    for part in dnsName:
        
        segmentedName = wordsegment.segment(part)
        for word in segmentedName:
            try:
                if wordsegment.UNIGRAMS[word] > 0 and len(word)>maxLength: 
                    maxLength = len(word)
            except Exception:
                continue

    
       
    LMSlengthPercent=maxLength/sizeofList(dnsName)
 
    return LMSlengthPercent



def extractData(filename, delim):
    count=0
    data = []
    reader = csv.reader(open(filename), delimiter=delim)
    for row in reader:
        data.append(row[0])
        count=count+1
    
    return data

def percentNum(dnsName):
    d=len(dnsName)

    n=sum(c.isdigit() for c in dnsName)

    percent=n/d
    
    return percent

def dotRatio(dnsName):
    dotNumber = dnsName.count('.')
    return dotNumber/len(dnsName)

def sldLength(dnsName):
    return len(dnsName.split('.')[-1])



def calcParam(dnsName, prevdnsName):
    params=[]
    if prevdnsName is None:
        prevdnsName = dnsName
    
    params.append(len(dnsName))
    params.append(percentNum(dnsName))
    params.append(wordCalc(dnsName))
    params.append(LMSlength(dnsName))
    params.append(entropyCalc(dnsName))
    params.append(vTcRatioCalc(dnsName))
    params.append(dotRatio(dnsName))


    
    params.append(flagDGA(dnsName)) #7
    params.append(isFirstDigit(dnsName))#8
    params.append(consDigRatio(dnsName))#9
    params.append(uniqueCharNum(dnsName))#10
    params.append(repCharRatio(dnsName))#11
    params.append(consonantSeq(dnsName))#12


    #params.append(distance(dnsName, prevdnsName))
    #print('PARAMS')
    #print(params)
    paramsNorm = np.array(params).reshape(1, -1)
    paramsNorm = preprocessing.normalize(paramsNorm)
    
    print('NORMALIZED:')
    print(paramsNorm)
    return paramsNorm


def previous(iterable):
    prevs, items = tee(iterable, 2)
    prevs = chain([None], prevs)
    return zip(prevs, items)
    

def geoTest(ipaddr):
    try:
        if (ipaddr[0] == ':' and ipaddr[1] == ':' and ipaddr[2] == 'f' and ipaddr[3] == 'f' and ipaddr[4] == 'f' and ipaddr[5] == 'f' and ipaddr[6] == ':'):
            ipaddr = ipaddr.replace('::ffff:','')
    except IndexError:
        return 'Error'
    try: 
        response = DbIpCity.get(ipaddr, api_key='free')

    except Exception:
        return 'Error'
        
    return response.country

def extractDate(Date):
    try:
        datetime_Date = datetime.strptime(Date, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        Date = Date[0:26]
        datetime_Date = datetime.strptime(Date, '%Y-%m-%d %H:%M:%S.%f')
        datetime_DateOutput = checkDate(datetime_Date)
    return datetime_Date

def threatEvaluateOnlyAPI(dnsName):
    whoisResults = whoisLookup(dnsName)   
    reg = whoisResults[0]
    creation_datePre = whoisResults[1]
    expiration_datePre = whoisResults[2]
    org = whoisResults[3]
    mas_indicators = []
    datetime_time = datetime.now()
    if (reg == 'No info' or reg == 'Error, domain is unavaible'):
        mas_indicators.append(1)
    else:
        mas_indicators.append(0)
    if (creation_datePre != 'Error, domain is unavaible' and creation_datePre != 'No info' and creation_datePre != 'WhoisError'):
        try:
            creation_date = checkDate(creation_datePre)
            creation_timedelta = datetime_time - creation_date
            delta_1 = creation_timedelta.days*24 + creation_timedelta.seconds/3600
            if (delta_1 <= 1):
                mas_indicators.append(1)
            else:
                mas_indicators.append(0)
        except TypeError:
            mas_indicators.append(1)
    else:
        mas_indicators.append(1)
        
        

    if (expiration_datePre != 'Error, domain is unavaible' and expiration_datePre != 'No info' and expiration_datePre != 'WhoisError'):
        try:
            expiration_date = checkDate(expiration_datePre)
            expiration_timedelta = expiration_date - datetime_time 
            delta_2 = expiration_timedelta.days
            if (delta_2 <= 1):
                mas_indicators.append(1)
            else:
                mas_indicators.append(0)
        except TypeError:
            mas_indicators.append(1)
    else:
        mas_indicators.append(1)
    
         
    if (org == 'Error, domain is unavaible' or org == 'No info'):
        mas_indicators.append(1)
    else:
        mas_indicators.append(0)
    
    return mas_indicators

    



def threatEvaluate(countryCheck, nxresult, reg, creation_datePre, expiration_datePre, org, time):
    
    intCountryCheck = int(countryCheck)
    intnxresult = int(nxresult)
    datetime_time = extractDate(time)
    queryType =''
    

    threatPoints = 0

    if (reg == 'No info' or reg == 'Error, domain is unavaible'):
        threatPoints += 1
    if (creation_datePre != 'Error, domain is unavaible' and creation_datePre != 'No info' and creation_datePre != 'WhoisError'):
        creation_date = checkDate(creation_datePre)
        creation_timedelta = datetime_time - creation_date
        if ((creation_timedelta.days*24 + creation_timedelta.seconds/3600) <= 1):
            threatPoints +=1

    if (expiration_datePre != 'Error, domain is unavaible' and expiration_datePre != 'No info' and expiration_datePre != 'WhoisError'):
        expiration_date = checkDate(expiration_datePre)
        expiration_timedelta = expiration_date - datetime_time 
        if (expiration_timedelta.days <= 1):
            threatPoints +=1

    
         
    if (org == 'Error, domain is unavaible' or org == 'No info'):
        threatPoints += 1
    if (intCountryCheck > 2):
        threatPoints +=1
    

    if (intnxresult > 1):
        threatPoints +=1
  
    
    
    

    if (threatPoints < 3):
        queryType = 'Benign'
    if (threatPoints > 2 ):
        queryType = 'Malicious'
    
    return queryType


def checkIPs(addrs):
    responseList = []
    for addr in addrs:
        geoTestResult = geoTest(addr)
        if geoTestResult == 'Error':
            return 0
        else:
            responseList.append(geoTest(addr))
    counter = collections.Counter(responseList)
    return len(counter)

def sendNotification(dnsName, answer, time, hostname, status,  image, country_number, registrar, creation_date, expiration_date, organistaion,  NXDOMAIN_query_count, domainStatus, queryType):
    content = (dnsName + answer + time + hostname + image)
    mail = smtplib.SMTP('smtp.gmail.com', 587)
    mail.ehlo()
    mail.starttls()
    mail.login('notificationdnstest@gmail.com', '123456dns')
    mail.sendmail('notificationdnstest@gmail.com', 'admtestdns123@gmail.com', content)
    mail.close()
    #adm mail pass 123456dns
def filterDGA():
    counter1 = 0
    domainsDict = {}
    NXDomainDict = {}
    dgaDomains = []
    dgaQuery = []
    dataset =[]
   
    flag = subprocess.call(["powershell.exe", "C:\\Users\\Yan\\Desktop\\diplom\\passivedns.ps1"])
    
    con = sqlite3.connect("./databases/passDNSnew12.db")
    cursor = con.cursor()
    cursor.execute("""SELECT DISTINCT query, answer, image, hostname FROM dns""")
    records = cursor.fetchall() 
    dataset = [row[0] for row in records]
    for row in records:

        if row[1] is None or row[1]=='':
        
            key = row[2]+'_LIMIT_'+row[3]
            NXDomainDict.setdefault(key, [])
            NXDomainDict[key].append('NXDOMAIN')   
        else:

            key = row[0]
            domainsDict.setdefault(key, [])
            domainsDict[key].append(row[1])
        

    con.close()
    clf = load(dumpName)
    for prevdnsName, dnsName in previous(dataset):
            if prevdnsName == dnsName:
                featuresNormalized = featuresNormalizedLast
            else:
                features = calcParam(dnsName, prevdnsName)
                featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
                print(type(featuresNormalized))
                print(featuresNormalized)
                featuresNormalizedLast = featuresNormalized
            counter1 += 1
            
            if (clf.predict(featuresNormalized)) == ['DGA'] and len(dnsName.split(".")) != 1:
                if dnsName in dgaDomains:
                    continue
                else:

                    dgaDomains.append(dnsName)
                
                
    print('NUMBER OF CHECKS')
    print(counter1) 
    
    con = sqlite3.connect("D:\databases\passDNSnew12.db")
    dgaQueries = []
    for dnsName in dgaDomains:

        
        cursor = con.cursor()
        cursor.execute("""SELECT * FROM dns WHERE query = ?""", (dnsName,))
    
        dgaQuery = [row for row in cursor.fetchall()]
        for query in dgaQuery:
            dgaQueries.append(query)
        
    con.close()
    con1 = sqlite3.connect("D:\databases\DGAclassified.db")
    
    cursor1 = con1.cursor()
    

    for queryRow in dgaQueries:
        cursor1.execute("SELECT query, answer,  time, hostname, status, image FROM suspicious WHERE query = ?  AND answer =? AND time = ? AND hostname = ?  AND status = ? AND image = ?", 
        (queryRow[0], queryRow[1], queryRow[2], queryRow[3], queryRow[4], queryRow[5]))
        result = cursor1.fetchone()
        if result:
            continue
        else:
            try: 
                countryCheck = checkIPs(domainsDict[queryRow[0]])

            except KeyError:
                countryCheck = 0
            
            test = queryRow[5]+'_LIMIT_'+queryRow[3]
            try:
                nxresult = len(NXDomainDict[test])
            except Exception:
                nxresult = 0
            whoisResults = whoisLookup(queryRow[0])
            
            reg = whoisResults[0]
            creation_date = whoisResults[1]
            expiration_date = whoisResults[2]
            org = whoisResults[3]
            queryType = threatEvaluate(countryCheck, nxresult, reg, creation_date, expiration_date, org, queryRow[2])
            if (reg == 'Error, domain is unavaible' and creation_date == 'Error, domain is unavaible' and expiration_date == 'Error, domain is unavaible' and org == 'Error, domain is unavaible'):
                domainStatus = 'Down'
            else:
                domainStatus ='Up'
            cursor1.execute("INSERT INTO suspicious (query , answer, time, hostname, status, image, country_number, registrar, creation_date, expiration_date, organisation, NXDOMAIN_query_count, domainStatus, queryType) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", 
            (queryRow[0], queryRow[1], queryRow[2], queryRow[3], queryRow[4], queryRow[5],  countryCheck, reg, creation_date, expiration_date, org, nxresult , domainStatus, queryType))
            if (queryType == 'Malicious'): 
                sendNotification(queryRow[0], queryRow[1], queryRow[2], queryRow[3], queryRow[4], queryRow[5],  countryCheck, reg, creation_date, expiration_date, org, nxresult , domainStatus, queryType)
    con1.commit()
    con1.close()

def checkName(dnsName):
    prevdnsName = dnsName
    features = calcParam(dnsName, prevdnsName)
    featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
    
    clf = load(dumpName)
    q = clf.predict_proba(featuresNormalized)
    print(q)



def switchMode(mode):
    switcher={

        '-h': lambda : help(),
        '-d': lambda : learnDump(),
        '-l': lambda : loadTest(),
        '-f': lambda: filterDGA(),
        '-tN': lambda: sendNotification('query' , 'answer', 'time', 'hostname', 'status', 'image', 'country_number', 'registrar', 'creation_date', 'expiration_date', 'organisation', 'NXDOMAIN_query_count', 'domainStatus', 'queryType'),
        '-tE': lambda: entropyCalc('yandex.ru'),
        '-dump': lambda: dumpParameters(),
        '-test': lambda: LMSlength('yandex-dmp-sync.rutarget.ru'),
        '-optimize': lambda: Optimize(),
        '-ratio': lambda: precisDBcalc(), 
        '-whois': lambda: whoisLookup('im0-tub-ru.yandex.net'),
        '-checkName': lambda : checkName('yandex.ru'),
        '-new': lambda: NewTest(),
        '-sldLength': lambda: sldLength('im0-tub-ru.yandex.net')
       

    }
    return switcher.get(mode, lambda :'Invalid')()


if __name__ == "__main__":

    if sys.argv[1]!='-h':
        dumpName='undefined.joblib'
        if sys.argv[2]=='-RF':
            dumpName='RF13.joblib'

        if sys.argv[2]=='-CART':
            dumpName='CARTdump.joblib'
        
        if sys.argv[2]=='-SVC':
            dumpName='SVCdump.joblib'
        
    
    mode = switchMode(sys.argv[1])
    
    
    
