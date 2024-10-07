"""Encrypted socket server implementation
   Author:
   Date:
"""

import socket
import protocol


def create_server_rsp(cmd):
    """Based on the command, create a proper response"""
    return "Server response"


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    # 1 - choose private key
    diffie_hellman_private_key = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    diffie_hellman_public_key = protocol.diffie_hellman_calc_public_key(diffie_hellman_private_key)
    # 3 - interact with client and calc shared secret
    client_socket.send(str(diffie_hellman_public_key).encode())
    diffie_hellman_other_public_key = int(client_socket.recv(1024).decode())
    diffie_hellman_shared_secret = protocol.diffie_hellman_calc_shared_secret(diffie_hellman_other_public_key, diffie_hellman_private_key)

    # RSA
    # Pick public key
    while True:
        rsa_public_key = protocol.get_RSA_public_key()
        if protocol.check_RSA_public_key((protocol.RSA_P -1) * (protocol.RSA_Q- 1), rsa_public_key):
            break
    # Calculate matching private key
    rsa_private_key = protocol.get_RSA_private_key(
    protocol.RSA_P, protocol.RSA_Q, rsa_public_key)
    # Exchange RSA public keys with client
    client_socket.send(str(rsa_public_key).encode())
    rsa_other_public_key = int(client_socket.recv(1024).decode())
    while True:
        # Receive client's message
        valid_msg, message = protocol.get_msg(client_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if client's message is authentic
        # 1 - separate the message and the MAC
        message = ".".split(message)
        # 2 - decrypt the message
        data  = protocol.symmetric_encryption(message[0], diffie_hellman_shared_secret)
        # 3 - calc hash of message
        data_hash  = protocol.calc_hash(data)
        # 4 - use client's public RSA key to decrypt the MAC and get the hash
        recive_signeture = protocol.calc_signature(message[1], rsa_other_public_key)
        # 5 - check if both calculations end up with the same result
        if  recive_signeture != data_hash:
            print("messege not authentic")
        else:
            print([data])
        if message == "EXIT":
            break

        # Create response. The response would be the echo of the client's message
        data_hashed = protocol.calc_hash(data)
        signature = protocol.calc_signature(data_hashed, rsa_private_key)

        # Encrypt
        # apply symmetric encryption to the server's message
        message = protocol.symmetric_encryption(data, diffie_hellman_shared_secret)
        # Send to client
        # Combine encrypted user's message to MAC, send to client
        msg += '.' + str(signature)
        msg = protocol.create_msg(message)
        client_socket.send(msg.encode())

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    print(protocol.calc_hash("555"))
    main()
