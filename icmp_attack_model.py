# -*- coding: utf-8 -*-
"""
Created on Thu Mar 12 23:54:10 2020

@author: hp
"""
import numpy as np
import pandas as pd
import pickle
import matplotlib.pyplot as plt

colnames = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
            "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
            "num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login",
            "is_guest_login","count","srv_count","serror_rate","srv_serror_rate","same_srv_rate","diff_srv_rate",
            "srv_diff_host_rate","una1","una2","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
            "dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
            "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","result"]

df = pd.read_csv('train_dataset.csv',',',header=None,names=colnames)
#print(df.head())
icmp_df = df[df.loc[:,'protocol_type']=='icmp']

features = ['duration','service','src_bytes','wrong_fragment','count','urgent',
            'num_compromised','srv_count']
target = 'result'

Y = icmp_df.loc[:,target]

classes = np.unique(Y)

for i in range(len(classes)):
    if classes[i]=='normal.':
        icmp_df = icmp_df.replace(classes[i],0)
    else :
        icmp_df = icmp_df.replace(classes[i],1)

icmp_df = icmp_df.replace('eco_i',-1)
icmp_df = icmp_df.replace('ecr_i',0)
icmp_df = icmp_df.replace('tim_i',1)
icmp_df = icmp_df.replace('urp_i',2)

X = icmp_df.loc[:,features]
Y = icmp_df.loc[:,target]

from sklearn.model_selection import train_test_split
X_train,X_test,Y_train,Y_test = train_test_split(X,Y,shuffle=True,test_size=0.3)

from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

model = DecisionTreeClassifier()
model.fit(X_train,Y_train)
Y_pred = model.predict(X_test)
acc = accuracy_score(Y_test,Y_pred)*100
print("accuracy: ",acc)

'''cm = confusion_matrix(Y_test,Y_pred)
report = classification_report(Y_test,Y_pred)
print('confusion matrix:\n',cm)
print('report:\n',report)'''

pickle.dump(model, open('icmp_model.pkl','wb'))
model = pickle.load(open('icmp_model.pkl','rb'))
print(model.predict(np.array([[0,0,1000,0,511,0,0,511]])))
print(model.predict(np.array([[0,1,100,0,200,0,0,2]])))
