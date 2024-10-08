"""Encrypted socket client implementation
   Author:
   Date:
"""

import socket
import protocol
RSA_P = 7879
RSA_Q = 11

def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    print("Connected")
    # Diffie Hellman
    # 1 - choose private key
    diffie_hellman_private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    diffie_hellman_public_key = protocol.diffie_hellman_calc_public_key(diffie_hellman_private_key)
    # 3 - interact with server and calc shared secret
    my_socket.send(str(diffie_hellman_public_key).encode())
    diffie_hellman_other_public_key = int(my_socket.recv(1024).decode())
    diffie_hellman_shared_secret = protocol.diffie_hellman_calc_shared_secret(
        diffie_hellman_other_public_key, diffie_hellman_private_key)

    # RSA
    # Pick public key
    while True:
        rsa_public_key = protocol.get_RSA_public_key()
        if protocol.check_RSA_public_key((RSA_P - 1) * (RSA_Q - 1), rsa_public_key):
            break
    # Calculate matching private key
    rsa_private_key = protocol.get_RSA_private_key(
        RSA_P, RSA_Q, rsa_public_key)
    # Exchange RSA public keys with server
    my_socket.send(str(rsa_public_key).encode())
    rsa_other_public_key = int(my_socket.recv(1024).decode())
    # Exchange RSA M with server
    my_socket.send(str(RSA_P*RSA_Q).encode())
    other_M = int(my_socket.recv(1024).decode())

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        mssage_hash = protocol.calc_hash(user_input) 
        # 2 - calc the signature
        signature = protocol.calc_signature(mssage_hash, rsa_private_key, RSA_P * RSA_Q)

        # Encrypt
        # apply symmetric encryption to the user's input
        msg = protocol.symmetric_encryption(user_input, diffie_hellman_shared_secret)
        print("user send encript is:" + msg)
        # Send to server
        # Combine encrypted user's message to MAC, send to server
        msg += '.' + str(signature)
        msg = protocol.create_msg(msg)
        msg = msg.replace('0', '1')
        my_socket.send(msg.encode())

        if user_input == 'EXIT':
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        message = message.split('.')
        # 2 - decrypt the message
        data = protocol.decode_binary_string(message[0])
        data  = protocol.symmetric_encryption(data, diffie_hellman_shared_secret)
        data = protocol.decode_binary_string(data)
        # 3 - calc hash of message
        data_hash  = protocol.calc_hash(data)
        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        recive_signeture = protocol.calc_signature(message[1], rsa_other_public_key, other_M)
        # 5 - check if both calculations end up with the same result    
        if  recive_signeture != data_hash:
            print("messege not authentic")
        else:
            print(data)
        # Print server's message

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
