from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split  #used for splitting the data to training and validation sets
from keras.models import Sequential #used to initiating the NN
from collections import Counter
import matplotlib.pyplot as plt #used for plotting
from keras.layers import Dense #used to initiating the NN
from keras.optimizers import * #used as a parameter in the NN layers
from keras import callbacks #a call back returns info during the process of training. Think of it as a training log
import pandas as pd #used to import the dataset
import numpy as np #used for arrays and some computations
from sklearn.metrics import confusion_matrix
import itertools
#Function taken from SciKit-Learn website
def plot_confusion_matrix(cm, classes,
                        normalize=False,
                        title='Confusion matrix',
                        cmap=plt.cm.Blues):
    """
    This function prints and plots the confusion matrix.
    Normalization can be applied by setting `normalize=True`.
    """
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)

    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, cm[i, j],
            horizontalalignment="center",
            color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    
    
def train_model():
    df = pd.read_csv('dataset_full.csv') 

    X=df.drop(columns=['phishing']) #X is all the columns of the dataset except the result
    X=X.values
    y=df.phishing
    df['phishing'] = df['phishing'].map({-1:0, 1:1})
    df['phishing'].unique()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=np.random.seed(7)) #use a test size of 20% of the dataset


    #Initiate the model
    model = Sequential()

    #The number of layers and units/layer used are from the OFS-NN paper (200-150-100-50-20-5-1 hidden units)
    model.add(Dense(200, activation='relu',
          kernel_initializer='uniform',input_dim=X.shape[1]))
    model.add(Dense(150, activation='relu',
          kernel_initializer='uniform'))
    model.add(Dense(100, activation='relu',
          kernel_initializer='uniform'))
    model.add(Dense(50, activation='relu',
          kernel_initializer='uniform'))
    model.add(Dense(20, activation='relu',
          kernel_initializer='uniform'))
    model.add(Dense(5, activation='relu',
          kernel_initializer='uniform'))
    model.add(Dense(1,  activation='sigmoid', 
          kernel_initializer='uniform'))
    model.compile(loss='binary_crossentropy', optimizer=Adam(), metrics=['accuracy'])

    es_cb = callbacks.EarlyStopping(monitor='loss', min_delta=0.001, patience=5) #A call back is , as mentioned above, used for logging training and gathering statistics
    history = model.fit(X_train, y_train, batch_size=60, epochs=100, verbose=1, callbacks=[es_cb])
    scores = model.evaluate(X_test, y_test)
    print('\nAccuracy score of the Neural Network with basic hyperparameter settings {0:.2f}%'.format(scores[1]*100))
    model.save("PhishingNet.h5")
    y_pred=model.predict_classes(X_test)
    cm = confusion_matrix(y_true=y_test, y_pred=y_pred)
    cm_plot_labels = ['Legit Website','Phishing Website']
    print(cm)
    plot_confusion_matrix(cm=cm, classes=cm_plot_labels, title='Confusion Matrix') 
    

    
    return model