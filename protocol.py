"""Encrypted sockets implementation
   Author:
   Date:
"""

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 4001
DIFFIE_HELLMAN_G = 25

# TO DO sprate client server p q



def symmetric_encryption(input_data, key):
    """Encrypt or decrypt the data using XOR method.
    The key is 16 bits. If the length of the input data is odd, use only the bottom 8 bits of the key."""
    if len(input_data) % 2 == 1:
        key = key & 0xFF  

    encrypted_data = []
    bin_key = format(key, '016b')

    # XOR each character's binary representation with the binary key
    for char in input_data:
        char_bin = format(ord(char), '08b')  
        encrypted_char = ''.join(str(int(char_bin[i]) ^ int(bin_key[i % len(bin_key)])) for i in range(8))
        encrypted_data.append(encrypted_char)

    
    return ''.join(encrypted_data)



def diffie_hellman_choose_private_key():
    """Choose a 16 bit size private key """
    private_key = int(input("please choose diffie_helman private key "))
    return private_key


def diffie_hellman_calc_public_key(private_key):
    """G**private_key mod P"""
    public_key = DIFFIE_HELLMAN_G**private_key % DIFFIE_HELLMAN_P
    return public_key


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """other_side_public**my_private mod P"""
    shared_seacret = other_side_public**my_private % DIFFIE_HELLMAN_P
    return shared_seacret


def calc_hash(message):
    result = 0
    for i in str(message):
        result += ord(i)
    result = result**0.5
    result = "".join((str(result).split('.')))
    result = bin(int(result))
    result = int(result[4:20], 2)
    return result


def calc_signature(hash, RSA_private_key, M):
    """Calculate the signature, using RSA alogorithm
    hash**RSA_private_key mod (P*Q)"""
    signature = (int(hash)**RSA_private_key) % M
    return signature


def create_msg(data):
    """Create a valid protocol message, with length field
    For example, if data = data = "hello world",
    then "11hello world" should be returned"""
    length = len(data)
    message = (str(length)).zfill(2) + data
    return message


def get_msg(my_socket):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    length = my_socket.recv(LENGTH_FIELD_SIZE).decode()
    if str(length).isdigit():
        return True, my_socket.recv(int(length)).decode()
    return False, "Error"


def check_RSA_public_key(totient, key):
    """Check that the selected public key satisfies the conditions
    key is prime
    key < totoent
    totient mod key != 0"""
    if key < totient and (totient % key) != 0:
        return True
    return False


def get_RSA_private_key(p, q, public_key):
    """Calculate the pair of the RSA public key.
    Use the condition: Private*Public mod Totient == 1
    Totient = (p-1)(q-1)"""
    Totient = (p-1) * (q-1)
    private_key = 0
    while True:
        if (private_key * public_key) % Totient == 1:
            break
        private_key += 1
    return private_key


def get_RSA_public_key():
    """Pick prime number to become public key"""
    while True:
        public_key = int(input("please choose RSA prime public key"))
        for i in range(2, int(public_key**0.5) + 1):
            if public_key % i == 0:
                print(" NOT PRIME ")
                break
            if i == int(public_key**0.5):
                return public_key

def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))