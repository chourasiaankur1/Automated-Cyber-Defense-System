# -*- coding: utf-8 -*-
"""
Created on Sat Mar 14 14:09:52 2020

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

tcp_syn_df = df[df.loc[:,"protocol_type"] == "tcp"]

tcp_syn_df = tcp_syn_df[tcp_syn_df.loc[:,"srv_serror_rate"] > 0.7]

#tcp_syn_df.head()

service_values = np.unique(tcp_syn_df.loc[:,"service"])
mid = (len(service_values)+1)/2
mid = int(mid)
for i in range(len(service_values)):
    tcp_syn_df = tcp_syn_df.replace(service_values[i], int(np.round((i-mid)/10)))
    
y = tcp_syn_df.loc[:,'result']
classes = np.unique(y)
for i in range(len(classes)):
    if classes[i] == 'normal.':
        tcp_syn_df = tcp_syn_df.replace(classes[i], 0)
    else:
        tcp_syn_df = tcp_syn_df.replace(classes[i], 1)

features = ["service","count","srv_count","src_bytes","serror_rate"]
target = "result"

X = tcp_syn_df.loc[:,features]
Y = tcp_syn_df.loc[:,target]

from sklearn.model_selection import train_test_split
X_train, X_test, Y_train, Y_test = train_test_split(X, Y,random_state=0,test_size=0.4,shuffle=True)

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

pickle.dump(model, open('tcp_model.pkl','wb'))
model = pickle.load(open('tcp_model.pkl','rb'))
print(model.predict(np.array([[-3,5,10,20000,1]])))
print(model.predict(np.array([[-1,500,500,0,1]])))



