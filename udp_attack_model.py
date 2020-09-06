# -*- coding: utf-8 -*-
"""
Created on Sat Mar 14 15:09:39 2020

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
udp_df = df[df.loc[:,'protocol_type']=='udp']

service_values = np.unique(udp_df.loc[:,"service"])
mid = (len(service_values)+1)/2
mid = int(mid)
for i in range(len(service_values)):
    udp_df = udp_df.replace(service_values[i], i-mid)

y = udp_df.loc[:,'result']
classes = np.unique(y)
for i in range(len(classes)):
    if classes[i] == 'normal.':
        udp_df = udp_df.replace(classes[i], 0)
    else:
        udp_df = udp_df.replace(classes[i], 1)

features = ["dst_bytes","service","src_bytes","dst_host_srv_count",
            "count"]
target = "result"

X = udp_df.loc[:,features]
y = udp_df.loc[:,target]

from sklearn.model_selection import train_test_split
X_train, X_test, Y_train, Y_test = train_test_split(X, y,shuffle=True,random_state=42, test_size=0.3)

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score

model = RandomForestClassifier()
model.fit(X_train,Y_train)
Y_pred = model.predict(X_test)
acc = accuracy_score(Y_test,Y_pred)*100
print("accuracy: ",acc)
'''cm = confusion_matrix(Y_test,Y_pred)
report = classification_report(Y_test,Y_pred)
print('confusion matrix:\n',cm)
print('report:\n',report)'''

pickle.dump(model, open('udp_model.pkl','wb'))
model = pickle.load(open('udp_model.pkl','rb'))
print(model.predict(np.array([[146,0,105,254,1]])))
print(model.predict(np.array([[146,0,105,254,2]])))
