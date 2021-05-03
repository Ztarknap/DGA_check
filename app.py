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
import sklearn.metrics as metrics
import matplotlib.pyplot as plt
import skfuzzy as fuzz
from sklearn.metrics import auc
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.model_selection import cross_val_score, train_test_split, RepeatedKFold, GridSearchCV
from sklearn.metrics import confusion_matrix, f1_score   
from sklearn.datasets import make_regression
from sklearn.ensemble import RandomForestRegressor
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from joblib import dump, load
from sklearn import tree, preprocessing, svm
from collections import Counter
from datetime import datetime
from sklearn.model_selection import StratifiedKFold
from Levenshtein import distance
from sklearn.metrics import plot_roc_curve
from ip2geotools.databases.noncommercial import DbIpCity
from math import log, e
from itertools import tee, islice, chain
from matplotlib import pyplot
from skfuzzy import control as ctrl


#avg_dga = 2.3809
avg_sum = 0.1515
np.set_printoptions(precision=6)

wordsegment.load()

start_time = time.time()

API_KEY = 'f6efc17a887ad7245fcff3458d45f257e290ceaa9d96f437920afad7cc3cb2ed'


def initFuzzy():
    
    whoisBased = ctrl.Antecedent(np.arange(0,5,1),'whoisBased')
    answerBased  = ctrl.Antecedent(np.arange(0,3,1),'answerBased')
    threatrating = ctrl.Consequent(np.arange(0, 11, 1), 'threatrating')

    
    whoisBased.automf(3, variable_type = 'quant', names = ['low', 'medium', 'high'])
    answerBased.automf(3, variable_type = 'quant', names = ['low', 'medium', 'high'])
    
    threatrating['low'] = fuzz.trimf(threatrating.universe, [0, 0, 5])
    threatrating['medium'] = fuzz.trimf(threatrating.universe, [0, 5, 10])
    threatrating['high'] = fuzz.trimf(threatrating.universe, [5, 10, 10])

    rule1 = ctrl.Rule(answerBased['low'] & whoisBased['low'] , threatrating['low'])
    rule2 = ctrl.Rule(answerBased['medium'] & whoisBased['medium'], threatrating['medium'])
    rule3 = ctrl.Rule(answerBased['high'] & (whoisBased['high']), threatrating['high'])


    
    rating_ctrl = ctrl.ControlSystem([rule1, rule2,  rule3])
    rating = ctrl.ControlSystemSimulation(rating_ctrl)

    return rating


def fuzzyDecide(whoisBasedpts, answerBasedpts, rating):
    rating.input['whoisBased'] = whoisBasedpts
    rating.input['answerBased'] = answerBasedpts
    
    rating.compute()
    result = rating.output['threatrating']
    return result

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
    datasetLegit=extractData('D:\\projects\\diploma\\test\\LegitTrainSet.php', '\n')
    datasetGenerated=extractData('D:\\projects\\diploma\\test\\GeneratedTrainSet.txt',',')
    x1=[]
    x2=[]
    

    for  prevdnsName, dnsName in previous(datasetLegit):
        x1.append(calcParam(dnsName, prevdnsName))
    
    for prevdnsName, dnsName in previous(datasetGenerated):
        x2.append(calcParam(dnsName, prevdnsName))
    print('Execution time ')
    print("--- %s seconds ---" % (time.time() - start_time))
    x1 = np.array(x1).reshape(np.array(x1).shape[0],-1)
    x2 = np.array(x2).reshape(np.array(x2).shape[0],-1)
    x1.tofile('./calculatedParametersLegitCombined25000_13.txt',sep = "\n")
    x2.tofile('./calculatedParametersGeneratedCombined25000_13.txt',sep = "\n")
    
    
def featuresFromFile(filename, delim, num_args):
    x = extractData(filename, delim)
    x = np.array(x).reshape(int(np.array(x).shape[0]/num_args),num_args)
    xFloat = x.astype(dtype = "float64")
    return xFloat





def checkDate(whoisdate):
    
    if (type(whoisdate) == list):
        return whoisdate[0]
        
    return whoisdate


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
    except Exception:
        if ping(dnsName) is True: #скорее всего тут тормоза происходят
            return ['WhoisError', 'WhoisError', 'WhoisError', 'WhoisError']
        else:
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
            creation_date = checkDate(whoisInfo.creation_date)
            whoisFeatures.append(creation_date)
        if whoisInfo.expiration_date is None:
            whoisFeatures.append('No info')
        else:
            expiration_date = checkDate(whoisInfo.expiration_date)
            whoisFeatures.append(expiration_date)
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
    print('первые аргументы')
    print('-d для обучения и дампа')
    print('-l для загрузки и проверки')
    print('-f для DGA фильтрации и вычисления параметров запросов')
    print('-optimize для оптимизации')
    print('вторые аргументы')
    print('-RF для режима RandomForest')
    print('-CART для режима CART')
    print('-SVC для режима SVC')
    
   
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

    
def featureImportanceCalc():
    datasetLegit=featuresFromFile('./calculatedParametersLegitCombined25000.txt', '\n', 13)
    datasetGenerated=featuresFromFile('./calculatedParametersGeneratedCombined25000.txt','\n', 13)
  
    
    y=[]

    x = np.concatenate((datasetGenerated, datasetLegit), axis = 0)
    

    for dnsName in datasetGenerated:
        y.append('DGA')

    for dnsName in datasetLegit:
        y.append('NORMAL')

    y = np.array(y).reshape(np.array(y).shape[0],-1)

    #x, y = make_regression(40000, 14, random_state = 1)

    clf = RandomForestClassifier()
    
    clf.fit(x, y)
    importance = clf.feature_importances_

    for i,v in enumerate(importance):
    	print('Feature: %0d, Score: %s.5f' % (i,v))

    #pyplot.bar([x for x in range(len(importance))], importance)
    #pyplot.show()

    permImp = permutation_importance(clf, x, y, n_repeats = 10, random_state = 1)
    
    print(permImp.importances_mean)
    perm_mas = permImp.importances_mean
    #pyplot.bar([x for x in range(len(perm_mas))], perm_mas)
    #pyplot.show()
    q = 3
    




def ROC_curve(clf, x, y):
    probs = clf.predict_proba(x)
    preds = probs[:,0]
    fpr, tpr, thresholds = metrics.roc_curve(y, preds,  pos_label = 'DGA')
    roc_auc = metrics.auc(fpr, tpr)
    t = roc_auc_score(y, preds)
    q = tpr - fpr
  
    ind = np.argmax(tpr - fpr)
    print(thresholds[ind])
    # method I: plt
    import matplotlib.pyplot as plt
    plt.title('Receiver Operating Characteristic')
    plt.plot(fpr, tpr, 'g', label = 'AUC1 = %0.2f' % roc_auc)
    plt.legend(loc = 'lower right')
    plt.plot([0, 1], [0, 1],'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
      
    plt.plot(fpr, tpr, 'b', label = 'AUC2 = %0.2f' % roc_auc)
    plt.legend(loc = 'lower right')

    plt.show()
    conf_matrix = confusion_matrix(y, clf.predict(x), labels = ['DGA', 'NORMAL'])


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

    datasetLegit=featuresFromFile('./calculatedParametersLegitCombined25000_14.txt', '\n',14 )
    datasetGenerated=featuresFromFile('./calculatedParametersGeneratedCombined25000_14.txt','\n',14)
  
    
    y=[]

    x = np.concatenate((datasetGenerated, datasetLegit), axis = 0)
    

    for dnsName in datasetGenerated:
        y.append('DGA')

    for dnsName in datasetLegit:
        y.append('NORMAL')
     
    y = np.array(y).reshape(np.array(y).shape[0],-1)

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 1)

    clf = RandomForestClassifier(random_state = 1)

    clf.fit(x_train, y_train)

    probs = clf.predict_proba(x)
    preds = probs[:,1]
    fpr, tpr, threshold = metrics.roc_curve(y, preds,  pos_label = 'NORMAL')
    roc_auc = metrics.auc(fpr, tpr)
    t1 = roc_auc_score(y, preds)
    # method I: plt

    
    plt.plot(fpr, tpr, 'b', label = 'AUC2 = %0.2f' % roc_auc)
    plt.legend(loc = 'lower right')

    plt.show()

    conf_matrix = confusion_matrix(y, clf.predict(x), labels = ['NORMAL', 'DGA'])


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

    q = 3

def ROC_Cross(classifier, X, y):

    cv = StratifiedKFold(n_splits = 10, shuffle = True,  random_state = 1)


    tprs = []
    aucs = []
    thresholds = []

    mean_fpr = np.linspace(0, 1, 100)

    fig, ax = plt.subplots()
    for i, (train, test) in enumerate(cv.split(X, y)):
        classifier.fit(X[train], y[train])
        viz = plot_roc_curve(classifier, X[test], y[test],
                            name='ROC fold {}'.format(i),
                            alpha=0.3, lw=1, ax=ax)
        interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
        interp_tpr[0] = 0.0
        tprs.append(interp_tpr)
        aucs.append(viz.roc_auc)

    ax.plot([0, 1], [0, 1], linestyle='--', lw=2, color='r',
            label='Chance', alpha=.8)

    mean_tpr = np.mean(tprs, axis=0)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    std_auc = np.std(aucs)
    ax.plot(mean_fpr, mean_tpr, color='b',
            label=r'Mean ROC (AUC = %0.2f $\pm$ %0.2f)' % (mean_auc, std_auc),
            lw=2, alpha=.8)

    std_tpr = np.std(tprs, axis=0)
    tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
    tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
    ax.fill_between(mean_fpr, tprs_lower, tprs_upper, color='grey', alpha=.2,
                    label=r'$\pm$ 1 std. dev.')

    ax.set(xlim=[-0.05, 1.05], ylim=[-0.05, 1.05],
        title="Receiver operating characteristic example")
    ax.legend(loc="lower right")
    plt.show()
    q = 3


def getProbas (clf, x):
    threshold = 0.5615
    #threshold = 0.44
    prob_preds = clf.predict_proba(x)
    preds = ['NORMAL' if prob_preds[i][1]>= threshold else 'DGA' for i in range(len(prob_preds))]
    return preds
def learnDump():
    
    datasetLegit=featuresFromFile('./calculatedParametersLegitCombined25000_14.txt', '\n',14)
    datasetGenerated=featuresFromFile('./calculatedParametersGeneratedCombined25000_14.txt','\n',14)
  
    
    y=[]

    x = np.concatenate((datasetGenerated, datasetLegit), axis = 0)
    

    for dnsName in datasetGenerated:
        y.append('DGA')

    for dnsName in datasetLegit:
        y.append('NORMAL')
     
    y = np.array(y).reshape(np.array(y).shape[0],-1)

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

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 1)

    
    #datasetLegitTest=featuresFromFile('./calculatedParametersLegitTest25000.txt', '\n')
    #datasetGeneratedTest=featuresFromFile('./calculatedParametersGeneratedTest25000.txt','\n')
  
    
    #y_test=[]

    #x_test = np.concatenate((datasetGeneratedTest, datasetLegitTest), axis = 0)
    

    #for dnsName in datasetGeneratedTest:
        #y_test.append('DGA')

    #for dnsName in datasetLegitTest:
        #y_test.append('NORMAL')




    #a = [100,10,100,10,100,10,100,10,100,10]
    #b = [55,55,55,55,55,55,55,55,55,55]
    #q1 = statistics.stdev(a)
    #q2 = statistics.stdev(b)
    #q3 = np.std(a)
   
    #ROC_Cross(clf, x, y)
    #y = np.array(y).reshape(np.array(y).shape[0],-1)
   
    #
    #clf.fit(x,y)
   
    #for train_index, test_index in cv.split(x,y):
        #x_train, x_test = x[train_index], x[test_index]
        #y_train, y_test = y[train_index], y[test_index]
        #clf.fit(x_train, y_train)
        #conf_matrix = confusion_matrix(y_test, clf.predict(x_test), labels = ['NORMAL', 'DGA'])
        #conf_matrix_list_of_arrays.append(conf_matrix)
    
    #mean_of_conf_matrix_arrays = np.mean(conf_matrix_list_of_arrays, axis = 0)
    clf.fit(x_train, y_train)
    #ROC_curve(clf, x_test, y_test)
    preds = getProbas(clf, x_test)
    #q = clf.predict(x_test)
    
    conf_matrix = confusion_matrix(y_test, preds, labels = ['DGA', 'NORMAL'])

    

    #ROC_curve(clf, x_test, y_test)


    #cv = StratifiedKFold(n_splits = 10, shuffle = True,  random_state = 1)
    #timeOfPrediction(clf, 'yandex.ru', 'vk.com')
    
   
    #conf_matrix_list_of_arrays = []
    #for val_train_index, val_test_index in cv.split(x_train,y_train):
        
        #val_x_train, val_x_test = x_train[val_train_index], x_train[val_test_index]
        #val_y_train, val_y_test = y_train[val_train_index], y_train[val_test_index]
        #clf.fit(val_x_train, val_y_train)
        #predict_mas = clf.predict(val_x_test) #подумать
        #onf_matrix = confusion_matrix(val_y_test, clf.predict(val_x_test), labels = ['NORMAL', 'DGA'])
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
    accuracy = (percent_mean_of_conf_matrix_arrays[0][0] + percent_mean_of_conf_matrix_arrays[1][1])/(percent_mean_of_conf_matrix_arrays[0][0]+percent_mean_of_conf_matrix_arrays[1][1]+ percent_mean_of_conf_matrix_arrays[0][1]+percent_mean_of_conf_matrix_arrays[1][0])
    precision = TP/(TP+FP)
    recall = TP/(TP+FN) 
    Fscore = 2*(precision*recall)/(precision+recall)
    
    
    
    #std_of_conf_matrix_arrays = np.std(conf_matrix_list_of_arrays, axis = 0)
    #conf_matrix = confusion_matrix(y_test, clf.predict(x_test), labels = ['DGA', 'NORMAL'])
    #print(mean_pf_conf_matrix)
    #dump(clf, dumpName)    
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
    
    params.append(len(dnsName))  #0
    params.append(percentNum(dnsName)) #1
    params.append(wordCalc(dnsName)) #2
    params.append(LMSlength(dnsName)) #3
    start_time_1 = time.time()
    params.append(entropyCalc(dnsName)) #4
    q1 = time.time() - start_time_1
    params.append(vTcRatioCalc(dnsName)) #5
    start_time_2 = time.time()
    params.append(dotRatio(dnsName)) #6
    q2 = time.time() - start_time_2
    start_time_3 = time.time()
    params.append(distance(dnsName, prevdnsName)) #7
    q3 = time.time() - start_time_3

    
    params.append(flagDGA(dnsName)) #8
    params.append(isFirstDigit(dnsName))#9
    params.append(consDigRatio(dnsName))#10
    params.append(uniqueCharNum(dnsName))#11
    params.append(repCharRatio(dnsName))#12
    params.append(consonantSeq(dnsName))#13


    
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

def threatEvaluate(countryCheck, nxresult, reg, creation_datePre, expiration_datePre, org, time, rating):

    intCountryCheck = int(countryCheck)
    intnxresult = int(nxresult)
    datetime_time = extractDate(time)
    queryType =''
    

    whoisPoints = 0
    answerPoints = 0
    

    if (reg == 'No info' or reg == 'Error, domain is unavaible'):
        whoisPoints += 1
    if (creation_datePre != 'Error, domain is unavaible' and creation_datePre != 'No info' and creation_datePre != 'WhoisError'):
        creation_date = checkDate(creation_datePre)
        creation_timedelta = datetime_time - creation_date
        if ((creation_timedelta.days*24 + creation_timedelta.seconds/3600) <= 1):
            whoisPoints +=1

    if (expiration_datePre != 'Error, domain is unavaible' and expiration_datePre != 'No info' and expiration_datePre != 'WhoisError'):
        expiration_date = checkDate(expiration_datePre)
        expiration_timedelta = expiration_date - datetime_time 
        if (expiration_timedelta.days <= 1):
            whoisPoints +=1

    
         
    if (org == 'Error, domain is unavaible' or org == 'No info'):
        whoisPoints += 1

    if (intCountryCheck > 2):
        answerPoints +=1
    

    if (intnxresult > 1):
        answerPoints +=1
  
    
    
    

    #if (threatPoints < 3):
        #queryType = 'Benign'
    #if (threatPoints > 2 ):
        #queryType = 'Malicious'
    

    fuzzy_result = fuzzyDecide(whoisPoints, answerPoints, rating)
    
    if fuzzy_result > 5:
        queryType = 'Malicious'
    else: 
        queryType ='Benign'


    return queryType

def ping(dnsName):
    command = ['ping', '-n', '1', dnsName]
    return subprocess.call(command) == 0

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

def sendNotification(dnsName, answerPre, time, hostname, status,  image, country_number, registrar, creation_date, expiration_date, organistaion,  NXDOMAIN_query_count, domainStatus, queryType):
    answer = ''
    if answerPre is None:
        answer = 'None'
    if answerPre == '':
        answer = 'None'
    else:
        answer = answerPre
    msg = f"""\
    Subject: Security Notification\n
    To: admtestdns123@gmail.com'
    From: notificationdnstest@gmail.com
    \nMalicious DGA query {dnsName} detected at {hostname} from {image} . Domain resolved in {answer} , time of query is {time} . Domain is {domainStatus}"""
    #msg.set_content('Malicious DGA query '+ dnsName + ' detected at '+ hostname + ' from ' + image + '. Domain resolved in ' + answer + ', time of query is ' + time + '. Domain is ' + domainStatus) 
    mail = smtplib.SMTP('smtp.gmail.com', 587)
    mail.ehlo()
    mail.starttls()
    mail.login('notificationdnstest@gmail.com', '123456dns')
    mail.sendmail('notificationdnstest@gmail.com', 'admtestdns123@gmail.com', msg)
    mail.close()
    #adm mail pass 123456dns
def filterDGA():

    fuzzy_rating = initFuzzy()

    counter1 = 0
    domainsDict = {}
    NXDomainDict = {}
    whoisDict = {}
    dgaDomains = []
    dgaQuery = []
    dataset =[]
    whoisLookupCounter = 0
    flag = subprocess.call(["powershell.exe","C:\\Users\\Server\\Documents\\DGAcheck\\db\\passivedns.ps1"])
    clf = load(dumpName)
    con = sqlite3.connect("C:\\Users\\Server\\Documents\\DGAcheck\\db\\psvDNS.db")
    cursor = con.cursor()
    cursor.execute("""SELECT DISTINCT query, answer FROM dns WHERE class IS ?""", (None,))
    records = cursor.fetchall() 
    dataset = [row[0] for row in records]
    for row in records:

        if row[1] is not None and row[1]!='':

            key = row[0]
            domainsDict.setdefault(key, [])
            domainsDict[key].append(row[1])
        

    
    clf = load(dumpName)
    for prevdnsName, dnsName in previous(dataset):
            if prevdnsName == dnsName:
                featuresNormalized = featuresNormalizedLast
            else:
                features = calcParam(dnsName, prevdnsName)
                featuresNormalized = np.array(features).reshape(np.array(features).shape[0],-1)
                featuresNormalizedLast = featuresNormalized
            counter1 += 1
            
            if (clf.predict(featuresNormalized)) == ['DGA'] and len(dnsName.split(".")) != 1:
                if dnsName in dgaDomains:
                    continue
                else:

                    dgaDomains.append(dnsName)
                
                
    print('NUMBER OF CHECKS')
    print(counter1) 
    
    
    dgaQueries = []
    for dnsName in dgaDomains:

        
        
        cursor.execute("""SELECT * FROM dns WHERE query = ?""", (dnsName,))
    
        dgaQuery = [row for row in cursor.fetchall()]
        
        for query in dgaQuery:
            if query[2] is None or query[1] == '':
                key = query[4]+'_LIMIT_'+query[6]
                NXDomainDict.setdefault(key, [])
                NXDomainDict[key].append('NXDOMAIN') 
            dgaQueries.append(query)
        
    
    

    for queryRow in dgaQueries:
        cursor.execute("SELECT ID from suspicious WHERE parentRecord = ?", 
        (queryRow[0],))
        result = cursor.fetchone()
        if result:
            continue
        else:
            try: 
                countryCheck = checkIPs(domainsDict[queryRow[1]])

            except KeyError:
                countryCheck = 0
            
            keyCombination = queryRow[4]+'_LIMIT_'+queryRow[6]
            try:
                nxresult = len(NXDomainDict[keyCombination])
            except Exception:
                nxresult = 0
            key = queryRow[1]
            if (whoisDict.get(key) is not None):
                whoisResults = whoisDict[key]
                reg = whoisResults[0]
                creation_date = whoisResults[1]
                expiration_date = whoisResults[2]
                org = whoisResults[3]

            else:
                whoisResults = whoisLookup(queryRow[1])
                            
                reg = whoisResults[0]
                creation_date = whoisResults[1]
                expiration_date = whoisResults[2]
                
                if (type(whoisResults[3]) == list):
                    org = whoisResults[3][0]
                else:
                    org = whoisResults[3]
                whoisDict.setdefault(key,  [reg, creation_date, expiration_date, org])
                whoisLookupCounter+=1
                print(queryRow[1])
                print(whoisLookupCounter)
               

            
            queryType = threatEvaluate(countryCheck, nxresult, reg, creation_date, expiration_date, org, queryRow[3], fuzzy_rating)
            if (reg == 'Error, domain is unavaible' and creation_date == 'Error, domain is unavaible' and expiration_date == 'Error, domain is unavaible' and org == 'Error, domain is unavaible'):
                domainStatus = 'Down'
            else:
                domainStatus ='Up'
            cursor.execute("INSERT INTO suspicious (query , answer, time, hostname, status, image, country_number, registrar, creation_date, expiration_date, organisation, NXDOMAIN_query_count, domainStatus, queryType, parentRecord) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", 
            (queryRow[1], queryRow[2], queryRow[3], queryRow[4], queryRow[5], queryRow[6],  countryCheck, reg, creation_date, expiration_date, org, nxresult , domainStatus, queryType, queryRow[0]))
            if (queryType == 'Malicious'): 
                sendNotification(queryRow[1], queryRow[2], queryRow[3], queryRow[4], queryRow[5], queryRow[6],  countryCheck, reg, creation_date, expiration_date, org, nxresult , domainStatus, queryType)
        
    for dnsName in dgaDomains:
            cursor.execute("UPDATE dns SET class = 'DGA' WHERE query = ?", (dnsName,))   
    cursor.execute("UPDATE dns SET class = 'REAL' WHERE class IS ?", (None,))   
    con.commit()
    con.close()


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
        '-sldLength': lambda: sldLength('im0-tub-ru.yandex.net'),
        '-importance': lambda: featureImportanceCalc()
       

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
    
    
    
