"""Encrypted socket client implementation
   Author:
   Date:
"""

import socket
import protocol


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    print("Connected")
    # Diffie Hellman
    # 1 - choose private key
    diffie_hellman_private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    diffie_hellman_public_key = protocol.diffie_hellman_calc_public_key(
        diffie_hellman_private_key)
    # 3 - interact with server and calc shared secret
    my_socket.send(str(diffie_hellman_public_key).encode())
    diffie_hellman_other_public_key = int(my_socket.recv(1024).decode())
    diffie_hellman_shared_secret = protocol.diffie_hellman_calc_shared_secret(
        diffie_hellman_other_public_key, diffie_hellman_private_key)

    # RSA
    # Pick public key
    while True:
        rsa_public_key = protocol.get_RSA_public_key()
        if protocol.check_RSA_public_key(rsa_public_key):
            break
    # Calculate matching private key
    rsa_private_key = protocol.get_RSA_private_key(
        protocol.RSA_P, protocol.RSA_Q, rsa_public_key)
    # Exchange RSA public keys with server
    my_socket.send(str(rsa_public_key).encode())
    rsa_other_public_key = int(my_socket.recv(1024).decode())

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        mssage = protocol.calc_hash(user_input) 
        # 2 - calc the signature
        signature = protocol.calc_signature(mssage, rsa_private_key)

        # Encrypt
        # apply symmetric encryption to the user's input
        user_input = protocol.symmetric_encryption(user_input, diffie_hellman_shared_secret)
        # Send to server
        # Combine encrypted user's message to MAC, send to server
        msg = protocol.create_msg(user_input)
        msg += str(signature)
        my_socket.send(msg.encode())

        if user_input == 'EXIT':
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        # 2 - decrypt the message
        # 3 - calc hash of message
        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        # 5 - check if both calculations end up with the same result

        # Print server's message

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
