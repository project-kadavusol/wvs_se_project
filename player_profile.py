'''import pymongo
from bson import ObjectId
myclient = pymongo.MongoClient("mongodb+srv://web_vul:web_vul@team20.znx7o.mongodb.net/")
mydb = myclient["wvs"]
mycol=mydb["user_data"]
username="naveen"
password="naveen"
mydict= {"name":username,"pass":password}
find={"_id"}
cond=mycol.find_one(mydict)
x=mycol.find_one(mydict,find)
z=mycol.find_one(x,{'_id':0,'name':1,'mail':1})
print(x)
y=list(x.values())
print(y[0])
usr="679f0550390588d1497883c9"
user = mycol.find_one({'_id': ObjectId(usr)}, {'_id': 0, 'name': 1})
z=mycol.find_one(y[0],{'_id':0,'name':1,'email':1})
name = user.get('name')  # Extract username
target="192.168.6.133"
col = mydb[name]
file_doc = col.find_one({"target": target})

if file_doc:
    file_data = file_doc["file_data"]  # Get the binary file content
    filename = file_doc["filename"]    # Get the original filename
    
    # Save the file locally
    with open(filename, "wb") as f:
        f.write(file_data)

    print(f"File '{filename}' has been restored from MongoDB.")
else:
    print("File not found in MongoDB.")
'''

word = input("Enter a string:")
def rev(str1):
    str2= " "
    i=len(str1)-1
    while i>=0:
        str2+=str1[i]
        i=i-1
    return str2
print("The Mirror image of the given string is:",rev(word))