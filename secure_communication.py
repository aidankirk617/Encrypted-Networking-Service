##
# Authors: Aidan Kirk, Ethan Mays
# Version: 11/30/22
#
# Description: This program serves as a secure messaging service between a sender and reciever
# written in python. Users are able to generate and view RSA key pairs, as well as use said keys
# to send and receive encrypted messages over the network through the use of public and private
# keys. This program heavily implements the pycryptodome library.
##

# Imports
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from random import seed, randint
import socket
from ipaddress import ip_address

# Constants
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
PADDED_IV = 32
AES_KEY_SIZE = 16
BYTES = 8
LARGE_KEY = 256
MED_KEY = 192
SMALL_KEY = 128
INT_BYTE_SIZE = 4
PADDED_INT_SIZE = 16
NONCE_MAX_BYTES = 2
HEX_BASE = 16
DIGEST_SIZE = 32
PADDED_DIGEST = 48
MAX_INT = 65535

def menu():
    """
    Allows user to select various functions of the program through a menu interface
    """
    print("===Secure Communicator===")
    print("----Main Menu----")
    print("1: Generate RSA Key Pair \n2: View RSA Key Pairs\n3: Send Message\n4: Receive Message"
          "\n0: Exit")


def do_option(option):
    """
    Responds to a menu option by calling the appropriate function. If an option
    that is <= 0 and > 4  or not an int is specified, an error message will be
    printed.
    Args:
        option : (int) The selected option.
    """
    if option == '1':
        gen_rsa_key_pair()
    elif option == '2':
        view_rsa_key_pairs()
    elif option == '3':
        send()
    elif option == '4':
        receive()
    elif option == '0':
        print("Program closed!")
        exit()
    else:
        print("\nError: Invalid option!\n")

def main():
    """
    Main method of the program
    """
    menu()
    first_msg = True
    option = input("Enter Option: ")
    while option != 0:
        do_option(option)
        menu()
        option = input("Enter Option: ")

    print("Goodbye!")


def gen_rsa_key_pair():
    """
    Creates a set of RSA encryption keys (public, private). Makes use of the Crypto.PublicKey module.
    """
    file_name = ""
    is_empty = True

    # Loop continuously until user inputs proper filename
    while is_empty:
        # Prompt user for filename
        file_name = input("Enter name for key pair: ")
        # Make sure filename is properly inputted
        if file_name != "":
            is_empty = False

    # Generate RSA keys
    keys = RSA.generate(RSA_KEY_SIZE)

    # Remove the .rsa extension
    if RSA_EXTN in file_name:
        file_name = file_name.replace(RSA_EXTN, "")

    # Create filenames and give them their extensions
    prv_name = MY_KEYS_DIR + file_name + "_prv" + RSA_EXTN
    pub_name = MY_KEYS_DIR + file_name + "_pub" + RSA_EXTN

    # Open the public and private key files
    prv_file = open(prv_name, "wb")
    pub_file = open(pub_name, "wb")

    # Convert files to PEM format
    prv_file.write(keys.exportKey("PEM"))
    pub_file.write(keys.public_key().exportKey("PEM"))

    # Close keys
    prv_file.close()
    pub_file.close()

    # Let user know both keys have been generated
    print("Key pair", prv_name, "and", pub_name, "generated")


def view_rsa_key_pairs():
    """
    Lists all .rsa files in the 'my_key_pairs directory'.
    """
    own_pairs_list = file_lister(MY_KEYS_DIR, RSA_EXTN)

    # Show all RSA key pairs
    print("\n======RSA Key Pairs======\n")
    print_list(own_pairs_list)


def view_pub_rsa_keys():
    """
    List all public keys
    """
    all_pairs = file_lister(MY_KEYS_DIR, RSA_EXTN)
    for key in all_pairs:
        if "_pub" not in key:
            all_pairs.remove(key)
    print("\n======Public Keys======\n")
    print_list(all_pairs)


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

def extract_nonce_seq(msg:bytes):
    """
    Gets the nonce and sequence numbers out of a message as bytes.
    Parameter:
        msg : (bytes) a message that has been received as bytes.
    Return:
        nonce, seq : (bytes) the nonce and sequence number as bytes.
    """
    nonce = msg[:PADDED_INT_SIZE]
    msg = msg[PADDED_INT_SIZE:]
    seq = msg[:PADDED_INT_SIZE]
    return [nonce, seq]

def extract_seed_and_iv(msg:bytes):
    """
    Gets the seed and IV out of a message as bytes.
    Parameter:
        msg : (bytes) a message that has been received as bytes.
    Return:
        crypto_seed, iv, aes_key : (bytes) the seed for rng, iv for aes key, and the aes key itself
        all as bytes.
    """
    crypto_seed = msg[:PADDED_INT_SIZE]
    msg = msg[PADDED_INT_SIZE:]
    iv = msg[:PADDED_IV]
    aes_key = msg[PADDED_IV:]
    return [crypto_seed, iv, aes_key]

def extract_ciphers(msg:bytes):
    """
    Extracts the cipher out of a message as bytes
    Parameter:
        msg : (bytes) a message that has been received as bytes.
    Return:
        nonce_and_sequence, remainder : (bytes) the nonce and sequence number together as bytes and
        the rest of the message.
    """
    nonce_and_sequence = msg[:PADDED_INT_SIZE * 2]
    remainder = msg[PADDED_INT_SIZE * 2:]
    return [nonce_and_sequence, remainder]

def extract_common_response(msg:bytes):
    """
    Gets the nonce and sequence numbers out of a message as bytes.
    Parameter:
        msg : (bytes) a message that has been received as bytes.
    Return:
        nonce, seq, digest, msg : (bytes) the nonce and sequence number and
        the digest and msg as bytes.
    """
    nonce, seq = extract_nonce_seq(msg)
    digest_and_msg = msg[PADDED_INT_SIZE * 2:]
    digest = digest_and_msg[:PADDED_DIGEST]
    msg = digest_and_msg[PADDED_DIGEST:]
    return [nonce, seq, digest, msg]

def unpad_all(padded_items: list):
    """
    Unpads everything in the tuple.
    Parameter:
        padded_items: (tuple) some padded items.
    Return:
        padded_items: (tuple) the items that are now unpadded.
    """
    index = 0
    for item in padded_items:
        padded_items[index] = unpad(item, AES.block_size)
        index += 1
    return padded_items

def pad_all(unpadded_items: list):
    """
    Pads all the items.
    Parameter:
        unpadded_items: (tuple) some unpadded data.
    Return:
        unpadded_items: (tuple) the items that are now padded.
    """
    index = 0
    for item in unpadded_items:
        unpadded_items[index] = pad(item, AES.block_size)
        index += 1
    return unpadded_items


def get_pub_key_path():
    """
    Helper method to get the file path of a public key and check if it is valid.
    Returns:
        The path to the valid public key
    """
    # display all the public keys
    view_pub_rsa_keys()
    # prompt for the key
    pub_key = ""
    key_is_invalid = True
    while key_is_invalid:
        pub_key = input('Select public key: ')
        if os.path.exists(MY_KEYS_DIR + pub_key) and "_pub" in pub_key:
            key_is_invalid = False
        else:
            print("Error: Invalid Key")
    return MY_KEYS_DIR + pub_key

def get_prv_key_path():
    """
    Helper method to get the file path of a private key and check if it is valid.
    Returns:
        The path to the valid private key
    """
    # display all the public keys
    view_pub_rsa_keys()
    # prompt for the key
    pub_key = ""
    key_is_invalid = True
    while key_is_invalid:
        pub_key = input('Select public key: ')
        if os.path.exists(MY_KEYS_DIR + pub_key) and "_pub" in pub_key:
            key_is_invalid = False
        else:
            print("Error: Invalid Key")
    return MY_KEYS_DIR + pub_key

def mess_length(mess):
    """
    Helper method to determine if a message is too long to send.
    Args:
        mess: the message to check

    Returns: True if it is too long, False otherwise
    """
    if len(mess) > MAX_LENGTH:
        print("Message longer than maximum allowed length")
        return True
    return False

def get_message():
    """
    Method for getting the message the user wants to send to the server.
    Return: message (bytes) = the message the user wants to send as bytes
    """
    valid = False
    message = ""
    while not valid:
        #ask user for message and see if it is an appropriate length
        message = input("Enter Message (max 4096 characters): ")
        if len(message) <= MAX_LENGTH:
            valid = True
    #convert to bytes then return
    message = bytes(message, "utf-8")
    return message


def get_ip_send():
    """
    Helper method to get the ip of the recipient for the sender and check if it is valid.
    Returns: The valid ip
    """
    ip = None
    is_invalid_ip = True
    while is_invalid_ip:
        ip = input("Type Recipient IP: ")
        try:
            # ip_address() throws an error if it is not given a valid address
            val = ip_address(ip)
            is_invalid_ip = False
        except ValueError:
            print("Error not a valid IPv4 Address")
    return ip

def send():
    """
    Prompts user for recepient IP address, as well as the users message before sending it to the
    recipient.
    """
    # Assign public keys path to a variable for ease of use
    pub_key = get_pub_key_path()
    prv_key = pub_key.replace("_pub.rsa", "_prv.rsa")

    # Retrieve the IP address
    address = get_ip_send()

    # Open the public key
    f = open(pub_key, "rb")
    prv_file = open(prv_key, "rb")
    sock = None

    try:
        # Create the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set the sockets timeout
        sock.settimeout(TIMEOUT)

        # Connect the socket
        sock.connect((address, PORT))
        sock.settimeout(None)

        # Send the key over the network
        print("Sending public key...")
        sock.sendall(f.read())

        # Create the private key
        prv_key = RSA.importKey(prv_file.read())
        prv_cipher = PKCS1_OAEP.new(prv_key)

        # Get the response and decrypt
        sock.settimeout(TIMEOUT)
        decrypted_response = prv_cipher.decrypt(sock.recv(BUFF_SIZE))

        # Pull out the digest
        digest = decrypted_response[:PADDED_DIGEST]

        # Pull out the remainder
        decrypted_response = decrypted_response[PADDED_DIGEST:]

        # Separate the nonce and sequence from the remainder
        nonce_and_sequence, remainder = extract_ciphers(decrypted_response)

        # Pull out the nonce and sequence
        nonce, seq = extract_nonce_seq(nonce_and_sequence)

        # Pull out the seed, iv, and plain aes_key from the remainder
        crypto_seed, iv, aes_key = extract_seed_and_iv(remainder)

        # Unpad everything
        sha_cipher = SHA256.new(nonce + seq + crypto_seed + iv + aes_key)
        nonce, seq, crypto_seed, iv, digest, aes_key = unpad_all([nonce, seq, crypto_seed, iv, digest, aes_key])

        # Make an aes cipher object and SHA encryption object using the decrypted response above
        aes_enc = AES.new(aes_key, AES.MODE_CBC, iv)

        # Seed this end's random number generator and gets the sequence number and nonce
        seed(crypto_seed)
        seq = int(seq.decode("utf-8"))
        nonce = int(nonce.decode("utf-8"))

        # Make an expected nonce and sequence number and store two booleans indicating if they were correct
        expected_nonce = randint(0, MAX_INT)
        expected_seq = 1

        # See if we need to enter the while loop
        keep_messaging = False
        if nonce == expected_nonce and seq == expected_seq:
            if digest == sha_cipher.digest():
                keep_messaging = True
            else:
                print("Error: digest received did not match the digest of the data received")
        else:
            print("Error: the nonce or sequence number did not match the expected value\n"
                  "Nonce match: ", nonce == expected_nonce,
                  "\nSequence number match: ", seq == expected_seq)

        # Continuously send and receive messages until input says otherwise
        while keep_messaging:
            seq, nonce = respond(sock, aes_key, iv, seq, nonce)
            expected_seq, seq, expected_nonce, keep_messaging = get_response(sock, aes_key, iv, expected_seq, expected_nonce)

            if keep_messaging:
                user_input = "J"
                while user_input != "Y" and user_input != "N":
                    user_input = input("Respond (Y/N): ").capitalize()

                if user_input == "N":
                    keep_messaging = False
                    nonce = str(randint(0, MAX_INT)).encode("utf-8")
                    seq += 1
                    seq = str(seq).encode("utf-8")
                    end = pad(END_MSG.encode("utf-8"), AES.block_size)
                    hash_function = SHA256.new(end)
                    digest = hash_function.digest()
                    nonce, seq, digest, msg = pad_all([nonce, seq, digest, end])
                    aes_encryptor = AES.new(aes_key, AES.MODE_CBC, iv)
                    ciphertext = aes_encryptor.encrypt(nonce + seq + digest + msg)
                    sock.settimeout(None)
                    sock.sendall(ciphertext)

    # Throw error messages when appropriate
    except ConnectionRefusedError:
        print("Connection was refused.")
    except InterruptedError:
        print("Message sending error. Message not sent.")
    except TimeoutError:
        print("Message receipt failed.")
    except OSError:
        print("Message sending error. Could not connect.")
    finally:
        if sock is not None:
            sock.close()
            print("Connection closed.")


def receive():
    """
    Recipient user receives messages sent from the send() function.
    """
    # Constants
    address = get_ip_receive()
    sock = None

    try:
        # Create the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((address, PORT))

        # Begin listening on the socket
        sock.listen()
        print("Waiting for message...")

        # Accept connection upon arrival of public key
        conn, addr = sock.accept()
        with conn:
            print("Connected by " + addr[0])
            conn.settimeout(TIMEOUT)
            keep_messaging = True
            mess = conn.recv(BUFF_SIZE)

            # Execute once
            try:
                # Imports the message as a public key, makes aes key as bytes and creates AES object
                sender_pub_key = RSA.importKey(mess).publickey()
                pub_cipher = PKCS1_OAEP.new(sender_pub_key)

            except(ValueError, IndexError, TypeError):
                # If the import fails we can do nothing so make wait_to_receive false
                print("Initial message could not have been a public key. Exiting...\n")
                keep_messaging = False

            if keep_messaging:
                aes_key = get_random_bytes(AES_KEY_SIZE)
                aes_encryptor = AES.new(aes_key, AES.MODE_CBC)

                # Gets the aes object iv, makes a cryptographic seed, seeds the session for this user
                iv = pad(aes_encryptor.IV, AES.block_size)
                crypto_seed = get_random_bytes(INT_BYTE_SIZE)
                seed(crypto_seed)
                crypto_seed = pad(crypto_seed, AES.block_size)

                # Gets the first nonce of the sequence, makes a sequence number, encodes both
                nonce = randint(0, MAX_INT)
                seq = 1
                seq_send = pad(str(seq).encode("utf-8"), AES.block_size)
                nonce_send = pad(str(nonce).encode("utf-8"), AES.block_size)

                # Concatenates all the components together and encrypts it, and sends the cipher text
                msg = nonce_send + seq_send + crypto_seed + iv + pad(aes_key, AES.block_size)
                sha_cipher = SHA256.new(msg)
                digest = pad(sha_cipher.digest(), AES.block_size)
                cipher_text = pub_cipher.encrypt(digest + msg)
                conn.settimeout(None)
                conn.sendall(cipher_text)
                expected_seq = 0
                iv = unpad(iv, AES.block_size)
                expected_nonce = 0

            while keep_messaging:
                conn.settimeout(TIMEOUT)
                # Get and decrypt a response, then split and unpad everything

                expected_seq, seq, expected_nonce, keep_messaging = get_response(conn, aes_key, iv, expected_seq, expected_nonce)

                if keep_messaging:
                    user_input = "J"
                    while user_input != "Y" and user_input != "N":
                        user_input = input("Respond (Y/N): ").capitalize()

                    if user_input == "N":
                        keep_messaging = False
                        nonce = str(randint(0, MAX_INT)).encode("utf-8")
                        seq += 1
                        seq = str(seq).encode("utf-8")
                        end = pad(END_MSG.encode("utf-8"), AES.block_size)
                        hash_function = SHA256.new(end)
                        digest = hash_function.digest()
                        nonce, seq, digest, msg = pad_all([nonce, seq, digest, end])
                        aes_encryptor = AES.new(aes_key, AES.MODE_CBC, iv)
                        ciphertext = aes_encryptor.encrypt(nonce + seq + digest + msg)
                        conn.settimeout(None)
                        conn.sendall(ciphertext)
                        conn.close()
                        return
                    else:
                        seq, nonce = respond(conn, aes_key, iv, seq, nonce)

    # Error checking
    except TimeoutError:
        print("Timed out.")
    except InterruptedError:
        print("Message receiving error.")
    finally:
        if sock is not None:
            sock.close()


def respond(sock, aes_key, iv, seq, nonce):
    """
    Lets the user send a response back and includes code to create the encrypted message that gets sent,
    Including the nonce, sequence, digest and message.
    Args:
        sock : the socket
        aes_key : the aes key
        iv : the initialization vector
        seq : the sequence sent between sender and receiver
        nonce : the nonce generated for authenticity

    Returns:
        seq : the sequence sent between sender and receiver
        nonce : the nonce generated for authenticity
    """
    # Get plaintext and digest
    plaintext = pad(get_message(), AES.block_size)
    hash_function = SHA256.new(plaintext)
    digest = hash_function.digest()

    # Increment sequence number and get nonce
    seq += 1
    nonce = randint(0, MAX_INT)

    # Convert to bytes
    encoded_seq = str(seq).encode("utf-8")
    encoded_nonce = str(nonce).encode("utf-8")

    # Padding
    encoded_nonce, encoded_seq, digest, plaintext = pad_all([encoded_nonce, encoded_seq, digest, plaintext])

    # Encryption
    aes_encryptor = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_encryptor.encrypt(encoded_nonce + encoded_seq + digest + plaintext)

    # Send Message
    sock.settimeout(None)
    sock.sendall(ciphertext)
    sock.settimeout(TIMEOUT)

    return [seq, nonce]


def get_response(sock, aes_key, iv, expected_seq, expected_nonce):
    """
    Lets the user receive a response and unwraps the encrypted message that was sent.
    It also checks to be sure the digests match and that the nonce/sequence are whats expected.
    Args:
        sock : the socket
        aes_key : the AES key
        iv : the initialization vector
        expected_seq: the sequence expected between sender and receiver
        expected nonce: nonce expected to uphold authenticity

    Returns:
        expected_seq : the sequence expected between sender and receiver 
        seq : the sequence sent
        expected_nonce : nonce expected to uphold authenticity
        keep_messaging : whether or not the users will continue messaging
    """
    # Receive Message and Decryption
    aes_decryptor = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_msg = aes_decryptor.decrypt(sock.recv(BUFF_SIZE))

    # Unpadding
    nonce, seq, digest, msg = unpad_all(extract_common_response(decrypted_msg))

    # Convert to integer
    nonce = int(nonce.decode("utf-8"))
    seq = int(seq.decode("utf-8"))

    # Update Expected Nonce and Sequence Number
    expected_nonce = randint(0, MAX_INT)
    expected_seq += 2

    # Get New Digest For Comparison
    hash_function = SHA256.new(msg)
    comp_digest = hash_function.digest()

    # Unpad Message
    msg = unpad(msg, AES.block_size)

    keep_messaging = True

    # If the nonce and sequence number are as expected
    if nonce == expected_nonce and seq == expected_seq:
        # If the digests don't match
        if (digest != comp_digest):
            keep_messaging = False
            print("Error: The received hash and the hash of the plaintext did not match")
        # If the message is the end message
        elif msg.decode() == END_MSG:
            keep_messaging = False
        else:
            print("Message Received:\n", msg.decode(), "\n")

    else:
        keep_messaging = False
        print(seq)
        print(expected_seq)
        print("Error: Unexpected Nonce or Sequence Number\n"
              "Nonce match: ", nonce == expected_nonce ,
              "\nSequence Number match: ", seq == expected_seq)

    return [expected_seq, seq, expected_nonce, keep_messaging]


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
            # Throw error if not given a valid address
            if ip == "":
                is_invalid_ip = False
            else:
                val = ip_address(ip)
                is_invalid_ip = False

        # If valid IP is not provided throw error        
        except ValueError:
            print("Error not a valid IPv4 Address")
    return ip

if __name__ == "__main__":
    main()
