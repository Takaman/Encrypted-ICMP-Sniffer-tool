from distutils.core import setup
import py2exe
import socket 
import struct
import time
import re
import random
import requests
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from multiprocessing import Process
from socket import htons
from time import sleep
from Crypto import Random
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

setup(console=['ping.py'])