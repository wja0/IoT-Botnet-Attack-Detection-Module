import os
from tkinter import Image

import mglearn
import pandas as pd
import pydotplus as pydotplus
from sklearn.metrics import roc_curve, accuracy_score, precision_score, recall_score, f1_score, plot_confusion_matrix, auc
from sklearn.ensemble import RandomForestClassifier
import matplotlib.pyplot as plt
import time
import seaborn as sns
import gc
import joblib
from sklearn.model_selection import train_test_split
from sklearn.tree import export_graphviz

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
PATH = os.path.join("C:/Users/KIM_GANG_MIN/Desktop/DataSet")

def load_data(path, filename):
    csv_path = os.path.join(path, filename)
    return pd.read_csv(csv_path,low_memory=False)


time_1 = time.time()
train_df = load_data(PATH, "total_traffic.csv")
#train_df['attack'] = textToInt(train_df, 'category')
time_2 = time.time()
time_interval = time_2 - time_1
print("데이터 불러오기 & 데이터 셔플 시간: " + str(time_interval))


time_1 = time.time()
x = pd.get_dummies(train_df.drop(['ip','mac','t_port','d_port', 'attack'], axis=1))
print(x.columns)
y = train_df['attack']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size =0.3)
time_2 = time.time()
time_interval = time_2 - time_1
print("데이터 전처리 시간: " + str(time_interval))
print("x_train data length: " + str(len(x_train))+"\ny_train data length: " + str(len(y_train))+"\nx_test data length: " + str(len(x_test))+"\ny_test data length: " + str(len(y_test)))

del train_df
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
train_acc = rf_clf.score(x_train, y_train)
test_acc = rf_clf.score(x_test, y_test)
time_2 = time.time()
time_interval = time_2 - time_1
print("모델 평가 시간: " + str(time_interval))

print(f"Accuracy: {accuracy_score(y_test, pred):.3f}")  # 정확도
print(f"Precision: {precision_score(y_test, pred,average='micro'):.3f}")  # 정밀도
print(f"Recall: {recall_score(y_test, pred,average='micro'):.3f}")  # 재현율
print(f"F1-score: {f1_score(y_test, pred,average='micro'):.3f}")  # F1 스코어



joblib.dump(rf_clf, 'C:/Users/KIM_GANG_MIN/Desktop/DataSet/Model/RAN_renew.h5')

time_1 = time.time()
ftr_importances_values = rf_clf.feature_importances_
ftr_importances = pd.Series(ftr_importances_values, index = x_train.columns)
ftr_top20 = ftr_importances.sort_values(ascending=False)[:15]
time_2 = time.time()
time_interval = time_2 - time_1
print("중요 피처 시각화 시간: " + str(time_interval))

plt.figure(1, figsize=(8,6))
plt.title('Top 20 Feature Importances')
sns.barplot(x=ftr_top20, y=ftr_top20.index)
plt.figure(2, figsize=(8,6))
for i in y_test:
    if i != 0:
        i = 1

for i in pred:
    if i!= 0:
        i=1
fpr, tpr, thresholds = roc_curve(y_test, pred)
plt.plot(fpr, tpr, '--', label="Logistic Regression")
plt.plot([0,1], [0,1], 'k--')
plt.plot([fpr],[tpr],'r-',ms=10)
plt.show()

