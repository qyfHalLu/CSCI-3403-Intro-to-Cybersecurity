"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Kaiwen Chen, Qiuyang Fu



"""

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
import uuid
from Crypto.Cipher import PKCS1_OAEP
import time
from Crypto import Random
from Crypto.Random import random
import base64


iv = "M4TA4L\T<B;QFFLX"

host = "localhost"
port = 10001



# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    return os.urandom(16)


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    f = open("id_rsa.pub", "r")
    key = f.read().split(" ", 3)[1]
    f.close()
    pubRSAKey = RSA.importKey(open('id_rsa.pub','r').read())
    encrypted_key = str(pubRSAKey.encrypt(session_key, 32))
    return encrypted_key

# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    padded_message = pad_message(message)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return base64.b64encode(cipher.encrypt(padded_message))

# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    decoded_message = base64.b64decode(message)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(decoded_message)
    return unpad_message(decrypted_message).decode('utf-8')


# Sends a message over TCP
def send_message(sock, message):
    if not message:
        print("Can't send empty string")
        return
    if type(message) != bytes:
        message = message.encode()
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data

# Remove spaces
def unpad_message(m):
    return m.rstrip()


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        encrypted_message = encrypt_message(message,key)
        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        send_message(sock, encrypted_message)

        # TODO: Receive and decrypt response from server
        
        received_message = receive_message(sock)
        if received_message:
            print("client received_message", decrypt_message(received_message, aes_key))
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
