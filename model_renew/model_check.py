import os
import pandas as pd
import ids_ap as ids
from sklearn.model_selection import train_test_split
import time
import numpy as np
import joblib
from collections import Counter
import xgboost as xgb
#import tensorflow as tf
str_attack = ['Normal', 'Scan IN', 'Scan OUT']

def model_init():
    final_model = joblib.load('./RAN_in_out_2.h5')
    
    return final_model
    

def check_attack(x_traffic, final_model, host_ip):
    x_traffic = x_traffic.drop(['ip', 'mac','t_port', 'd_port'], axis = 1)
    y_traffic = final_model.predict(x_traffic)
    cnt = 0
    result = x_traffic
    result['attack'] = y_traffic
    
    for i in y_traffic:
        if i == 1 or i == 2:
           cnt = cnt + 1
        
   
    attack = True
    if cnt > 50:
        attack = True
        
    #print('Attack 0: '+str(len(result.loc[result['attack']==0])))
    #print('Attack 1: '+str(len(result.loc[result['attack']==1])))
    #print('Attack 2: '+str(len(result.loc[result['attack']==2])))
    #print('Attack 3: '+str(len(result.loc[result['attack']==3])))
    
    print("[*]Finish Botnet Attack Detection")
    for i in range(3):
        print('Attack %d (%s): %d' % (i,str_attack[i],len(result.loc[result['attack']== i ])))
    
    return attack, result
            

