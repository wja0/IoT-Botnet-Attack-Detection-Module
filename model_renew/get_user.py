import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from firebase_admin import auth
from pyfcm import FCMNotification

APIKEY = "AAAA7aJLMSQ:APA91bGNf83X0OmIatkt_Fs1xVWiLM8OzWRu38v_aipfkpIcLEufg5a_FIhD5EFX8SX75tas7M42kD_KE_WN7W5rWFSr98uPnqlEzdEob5b3pr8UI6-Ae7p3FCTDO7y6ajfjN_f1W_Bz"
push_service = FCMNotification(APIKEY)

def sendMessage(title, body,TOKEN):
    data_message = {
        "body" : body,
        "title": title
    }
    result = push_service.single_device_data_message(registration_id=TOKEN, data_message=data_message)
    print(result)





def inform_user():
    # bring uid
    cred = credentials.Certificate('h0neyp0t-firebase-adminsdk-wrhlp-cd02b8d173.json')
    firebase_admin.initialize_app(cred, {'databaseURL': 'https://h0neyp0t-default-rtdb.firebaseio.com/'})

    page = auth.list_users()
    SELECTED_USER = 'b@gmail.com'
    while page:
        for user in page.users:
            if user.email == SELECTED_USER :
                UID = user.uid
                print("User's UID: ", UID)
        page = page.get_next_page()

    # bring APIKEY
    ref = db.reference('USER/{}/TOKEN'.format(UID))
    TOKEN = ref.get()

    sendMessage("공격 위험 감지", "IoT 기기의 해킹이 의심됩니다! 전원을 껐다 켜주세요!!",TOKEN)
