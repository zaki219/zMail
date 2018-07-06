import os.path
import hashlib
user_data = {}
alphabet = "abcdefghijklmnopqrstuvwxyz"
#purpose: makes a txt file to store data
#inputs:users data in a text document with hasshed password
def write_file():
    f = open("accounts.txt","w")
    for user in user_data:
        info = user_data[user]
        f.write(user + "`" + info[0] + "`" + info[1] + "`")
        inbox = info[2]
        for item in inbox:
            f.write(item+ "^")
        f.write("\n")
    f.close()
#purpose: encodes the composed email
#hashes it and sets the perameters 
def encode(secretMessage, key):
    newAlphabet = alphabet[key:] + alphabet[:key]
    index = alphabet.find(secretMessage)
    if index < 0:
        return secretMessage
    else:
         return newAlphabet[index]
#perpuse: decodes the message
def decode(secretMessage, key):
    newAlphabet = alphabet[key:] + alphabet[:key]
    index = newAlphabet.find(secretMessage)
    if index < 0:
        return secretMessage
    else:
        return alphabet[index]
    
#Purpose: Returns the hashed version of the passcode using SHA-256
#Parameters: Password to be hashed
#Returns: Hashed password
def hash_password(password):
     b = bytes(password,'utf-8')
     hash_value = hashlib.sha256(b).hexdigest()
     return hash_value
#purpose takes input then directs the user to where the se=celtected to go
def email(username):
    message = input("Enter S to send a message and C to check inbox")
    if message == 'C':
        info = user_data[username]
        inbox = info[2]
        print("Your mail here: ")
        for item in inbox:
            print(item)
        password = input("Please enter your password to view your decrypted messages: ")
        if hash_password(password) == user_data[username][0]:
            for item in inbox:
                decrypted = ""
                for i in item:
                    decrypted += decode(i, 4)
            print(decrypted)
#purpose takes the user input for drafting a email and puts it under their recepents name
    elif message == "S":
        friend = input ("email account")
        if user_data.get(username):
            mail = input ("compose mail")
            encrypted = ""
            for i in range(0, len(mail)):
                encrypted += encode(mail[i], 4)
            info = user_data[friend]
            inbox = info[2]
            inbox.append(encrypted)
        else:
            print ("please enter valid user")

#perpose orginises the .txt file with the 
if os.path.exists("accounts.txt"):
    f = open("accounts.txt", "r")
    for line in f:
        words = line.split("`")
        emails = words[3][:-2].split("^")
        user_data[words[0]] = (words[1], words[2], emails)
    f.close()
#purpose stops the user at five attempts for the password
attempt = 5
message = input("Enter L to Create your accout and E to log in, Q to quit")
while (message=="L" or message == "E" and message != "Q") and attempt > 0:
    if message == "L":
        username =input ("Enter ZMail Account")
        birthday = input ("Enter Birthday")
        password = input ("Enter account Password")
        b = bytes(password,'utf-8')
        hash_value = hashlib.sha256(b).hexdigest()
        inbox = ["Welcome to Zmail!"]
        info = (hash_value, birthday ,inbox)
        user_data[username] = info
        print ("Accout Created")
    elif message == "E":
        username=input("Enter username")
        if not user_data.get(username):
            print("incorrect username")
            attempt-=1
            continue
        password = input ("Enter Password")
        b = bytes(password,'utf-8')
        hash_value = hashlib.sha256(b).hexdigest()
        info = user_data[username]
        if info[0] == hash_value:
            print ("seccessful Log in")
            email(username)            
        else:
            attempt-=1
            print("inccorect Try again")
    message = input ("Enter L to Create your accout and E to log in")

write_file()


