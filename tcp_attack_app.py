# -*- coding: utf-8 -*-
"""
Created on Fri Mar 13 00:22:54 2020

@author: hp
"""

import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle

app = Flask(__name__)
model = pickle.load(open('tcp_model.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('tcp_index.html')

@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''
    int_features = [int(x) for x in request.form.values()]
    final_features = [np.array(int_features)]
    prediction = model.predict(final_features)

    if prediction[0] == 0 :
        output = 'No attack has been detected.'
    else:
        output = 'DDoS Attack(II)-Tcp Attack has been detected' 

    return render_template('tcp_index.html', prediction_text=output)

if __name__ == "__main__":
    app.run(debug=True)