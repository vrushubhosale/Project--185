import hashlib
from simplecrypt import encrypt, decrypt
value = input()
value2 = value
def SHA256():
    result = hashlib.sha256(value.encode())
    print("encrypted data : ",result.hexdigest())
SHA256()
def MD5():
    result = hashlib.md5(value.encode())
    print("2. encrypted data : ",result.hexdigest())
MD5()
message = value2
hex_string = ''
def encryption():
    global hex_string
    ciphercode = encrypt('en01-2a1', message)
    hex_string = ciphercode.hex()
def decryption():
    global hex_string
    byte_str = bytes.fromhex(hex_string)
    original = decrypt("en01-2a1", byte_str)
    final_message = original.decode("utf-8")
    print("Decrypted : ", final_message)
encryption()
decryption()    