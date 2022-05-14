import os
import pandas as pd
from sklearn.metrics import roc_curve
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import time
import seaborn as sns
import gc
import joblib

PATH = os.path.join("C:/Users/KIM_GANG_MIN/Desktop/DataSet/Bot-IoT/Bot-IoT_Dataset/CSV/Traning and Testing Tets (5% of the entier dataset)/10-best features/10-best Training-Testing split")

def load_data(path, filename):
    csv_path = os.path.join(path, filename)
    return pd.read_csv(csv_path,low_memory=False)

def hexToInt_d(df, col):
    tmp_list = df[col]
    result_list =[]
    cnt = 0
    for i in tmp_list:
        if "0x" in i:
            result_list.append(int(i, 16))
        else:
            result_list.append(int(i))
        cnt = cnt+1

    return pd.DataFrame(result_list, columns=['dport'])

def hexToInt_s(df, col):
    tmp_list = df[col]
    result_list =[]
    cnt = 0
    for i in tmp_list:
        if "0x" in i:
            result_list.append(int(i, 16))
        else:
            result_list.append(int(i))
        cnt = cnt+1

    return pd.DataFrame(result_list, columns=['sport'])



time_1 = time.time()
train_df = load_data(PATH, "UNSW_2018_IoT_Botnet_Final_10_best_Training.csv")
train_df['dport'] = hexToInt_d(train_df, 'dport')
train_df['sport'] = hexToInt_s(train_df, 'sport')
test_df = load_data(PATH, "UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv")
test_df['dport']= hexToInt_d(test_df, 'dport')
test_df['sport'] = hexToInt_s(test_df, 'sport')
time_2 = time.time()
time_interval = time_2 - time_1
print("데이터 불러오기 시간: " + str(time_interval))

time_1 = time.time()
x_train = pd.get_dummies(train_df.drop(['attack', 'saddr','daddr','pkSeqID','seq','category','subcategory','min','mean','max', 'drate', 'srate','stddev'], axis=1))
time_2 = time.time()
time_interval = time_2 - time_1
print("교육 데이터 전처리 시간: " + str(time_interval))
y_train = train_df['attack']

time_1 = time.time()
x_test = pd.get_dummies(test_df.drop(['attack', 'saddr','daddr','pkSeqID','seq','category','subcategory','min','mean','max', 'drate', 'srate','stddev'], axis=1))
time_2 = time.time()
time_interval = time_2 - time_1
#x_test.insert(20,'subcategory_Data_Exfiltration', 0)
print("테스트 데이터 전처리 시간: " + str(time_interval))
y_test = test_df['attack']

del train_df
del test_df
gc.collect()

print("------랜덤 포레스트 시작------")
rf_clf = RandomForestClassifier(random_state=40)

time_1 = time.time()
rf_clf.fit(x_train, y_train)
time_2 = time.time()
time_interval = time_2 - time_1
print("교육 시간: " + str(time_interval))

time_1 = time.time()
pred = rf_clf.predict(x_test)
time_2 = time.time()
time_interval = time_2 - time_1
print("예측 시간: " + str(time_interval))

print(rf_clf.score(x_test, y_test))

joblib.dump(rf_clf, 'C:/Users/KIM_GANG_MIN/Desktop/DataSet/Model/random_froest.pkl')

time_1 = time.time()
ftr_importances_values = rf_clf.feature_importances_
ftr_importances = pd.Series(ftr_importances_values, index = x_train.columns)
ftr_top20 = ftr_importances.sort_values(ascending=False)[:20]
time_2 = time.time()
time_interval = time_2 - time_1
print("중요 피처 시각화 시간: " + str(time_interval))

plt.figure(1, figsize=(8,6))
plt.title('Top 20 Feature Importances')
sns.barplot(x=ftr_top20, y=ftr_top20.index)
plt.figure(2, figsize=(8,6))
fpr, tpr, thresholds = roc_curve(y_test, pred)
plt.plot(fpr, tpr, '--', label="Logistic Regression")
plt.plot([0,1], [0,1], 'k--')
plt.plot([fpr],[tpr],'r-',ms=10)
plt.show()

