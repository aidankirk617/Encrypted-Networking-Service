##
# CS325 Project 3
#
# Author: Aidan Kirk and Ethan Mays
#
# Version: 11/30/22
#
# Description: All helper files for the secure communication program
##

# Imports
import random
import secure_communication
import socket
import os
import sys
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from ipaddress import ip_address


# Magic Numbers
PORT = 65432
TIMEOUT = 30.0
MAX_LENGTH = 4096
BUFF_SIZE = 1024
END_MSG = "#<<END>>#"
MY_KEYS_DIR = "my_key_pairs/"
RSA_EXTN = ".rsa"  
AES_EXTN = ".aes"  
RSA_KEY_SIZE = 2048
IV_SIZE = 16
HASH_SIZE = 32
BYTES = 8
MED_KEY = 192


def file_lister(directory, extension):
    """
    Get all files of a particular extension in a directory
    Args:
        directory: The specified directory containing the files.
        extension: The specified file extension.

    Returns:
        All files of that particular extension.
    """
    # Append all files to a list
    file_list = []

    # Iterate through the directories and return the list
    for file in os.listdir(directory):
        if file.endswith(extension):
            file_list.append(file)
    return file_list
    
    
def print_list(file_list):
    """
    Format and print the filenames.
    Args:
        file_list : The list of files.
    """
    for item in file_list:
        print(item)
    print("\n")
    

def decrypt_with_prv(data):
    """
    """
    # Retrieve private key
    prv_key = get_key_path("_prv")
    plaintext = ""

    try:
        key_obj = RSA.importKey(prv_key)
        cipher = PKCS1_OAEP.new(key_obj)
        plaintext = cipher.decrypt(data)
    except (ValueError, IndexError, TypeError):
        print("Error")

    return plaintext
    
    
def get_key_path(key_type):
    """
    Checks the validity of a public or private key pair.
    Returns:
        The directory in which the keys are stored.
    """
    # View all public keys, view all key pairs
    if key_type == "_pub":
        view_pub_rsa_keys()
    else:
        view_rsa_key_pairs()

    # Prompt user for key, if incorrect deny access
    key = ""
    key_is_invalid = True
    while key_is_invalid:
        key = input('Select appropriate key: ')
        if os.path.exists(MY_KEYS_DIR + key) and key_type in key:
            key_is_invalid = False
        else:
            print("Error: Invalid Key")
    
    # Return directory in which keys are stored
    return MY_KEYS_DIR + key
    

def mess_length(mess):
    """
    Helper method to determine if a message is too long to send
    Args:
        mess: the message to check

    Returns: True if it is too long, False otherwise
    """
    if len(mess) > MAX_LENGTH:
        print("Message longer than maximum allowed length")
        return True
    return False
    
    
def get_ip_send():
    """
    Checks the recipients IP for validity.
    Returns: IP address 
    """
    # Constants
    ip = None
    is_invalid_ip = True

    # Prompt user for valid IP as long as it's invalid
    while is_invalid_ip:
        ip = input("Type Recipient IP: ")
        try:
            val = ip_address(ip)
            is_invalid_ip = False
        except ValueError:
            print("Error not a valid IPv4 Address")
    return ip
    
    
def get_ip_receive():
    """
    Checks the validity of the sender and receivers IP address.
    Returns: IP address
    """

    # Constants
    ip = None
    is_invalid_ip = True

    # Throw an error if given an invalid address, otherwise confirm validity
    while is_invalid_ip:
        ip = input("Enter IP Address of sender (leave empty for all): ")
        try:
            # ip_address() throws an error if it is not given a valid address
            if ip == "":
                is_invalid_ip = False
            else:
                val = ip_address(ip)
                is_invalid_ip = False

        # If valid IP is not provided throw error        
        except ValueError:
            print("Error not a valid IPv4 Address")
    return ip
