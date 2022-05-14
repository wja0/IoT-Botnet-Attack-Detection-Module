from keras.models import Sequential
from keras.layers import SimpleRNN, Dense, LSTM, Bidirectional
import os
import pandas as pd
from sklearn.model_selection import train_test_split
import time
import gc


os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
PATH = os.path.join("C:/Users/KIM_GANG_MIN/Desktop/DataSet")

def load_data(path, filename):
    csv_path = os.path.join(path, filename)
    return pd.read_csv(csv_path,low_memory=False)

def textToInt(df, col):
    tmp_list = df[col]
    result_list = []
    for i in tmp_list:
        if "scan" in i:
            result_list.append(1)
        elif "normal" in i:
            result_list.append(0)

    return pd.DataFrame(result_list, columns=['category'])

time_1 = time.time()
train_df = load_data(PATH, "all_scan_data.csv")
train_df['category'] = textToInt(train_df, 'category')
train_df = train_df.sample(frac=1).reset_index(drop=True)
time_2 = time.time()
time_interval = time_2 - time_1
print("데이터 불러오기 & 데이터 셔플 시간: " + str(time_interval))

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)

time_1 = time.time()
x = pd.get_dummies(train_df.drop(['saddr','daddr','src_mac', 'dst_mac','sport','category'], axis=1))
x = x.to_numpy()
x = x[..., None]

y = train_df['category']
y = y.to_numpy()
y = y[..., None]

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size =0.3, random_state = 1234)

time_2 = time.time()
time_interval = time_2 - time_1
print("데이터 전처리 시간: " + str(time_interval))
print("x_train data length: " + str(len(x_train))+"\ny_train data length: " + str(len(y_train))+"\nx_test data length: " + str(len(x_test))+"\ny_test data length: " + str(len(y_test)))

del train_df
gc.collect()

print("------RNN 시작------")
model = Sequential()
model.add(Bidirectional(LSTM(10, activation='relu')))
model.add(Dense(5))
model.add(Dense(1))
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['acc'])

time_1 = time.time()
model.fit(x_train,y_train, epochs=10, batch_size=128)
time_2 = time.time()
time_interval = time_2 - time_1
print("교육 시간: " + str(time_interval))

time_1 = time.time()
pred = model.predict(x_test)
time_2 = time.time()
time_interval = time_2 - time_1
print("예측 시간: " + str(time_interval))

score = model.evaluate(x_test, y_test)
print(score)

model.save('C:/Users/KIM_GANG_MIN/Desktop/DataSet/Model/RLSTM.h5')

