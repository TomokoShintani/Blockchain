from ecdsa import SigningKey
from ecdsa import SECP256k1
import time
import hashlib


def ask_confirmation():
    while True:
        ans = input("Do you verify the message you received? [ENTER y/n]:")
        if ans in ["y", "n"]:
            return ans
        else:
            print("Enter valid answer.")

class User:
    def __init__(self, name):
        self.name = name
        self.secret_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.secret_key.verifying_key
        self.mail_box ={}

    def send_data(self, data, receiver):
        data_bytes = bytes(data, encoding= "utf-8")
        self.mail_box[receiver.name] = History(self.name, data, data_bytes, receiver)
        hash_data = hashlib.sha256(data_bytes).digest() #これちゃんとdigestしないとbytesで返ってこないので注意
        signatured_data = self.secret_key.sign(hash_data)
        receiver.receive_data(self, signatured_data)

        
    def receive_data(self, sender, received_signed_data):
        confirmation = ask_confirmation()
        if confirmation == "y":
            self.verify_data(sender, received_signed_data)
        else:
            print("Verification interrupted.")

    def verify_data(self, sender, received_signed_data):
        data = sender.mail_box[self.name].open_data()
        true_data_bytes = sender.mail_box[self.name].data_bytes
        hash_true_data = hashlib.sha256(true_data_bytes).digest()
        print(sender.public_key.verify(received_signed_data, hash_true_data))
        print("Message: {} From: {}".format(data, sender.name))

class History:
    def __init__(self, sender, data, data_bytes, receiver):
        local_time = time.localtime(time.time())
        self.sended_time = time.strftime("%Y-%m-%d %H:%M:%S", local_time)
        self.sender = sender
        self.data = data
        self.data_bytes = data_bytes
        self.receiver = receiver
    def open_data(self): 
        return self.data
    
Amy = User('Amy')
Bob = User('Bob')
Amy.send_data("Hello", Bob)
print(Amy.mail_box['Bob'].sended_time)
