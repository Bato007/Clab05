from Crypto.Cipher import AES
from base64 import b64encode
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


'''
MODO CBC
-> Key 16 - La llave de 16 bits
-> txtToCipher - El nombre del archivo de texto a encriptar
-> txtToReturn - El nombre del archivo de texto que se returna
'''
def AEScipher(key16, txtToCipher, txtToReturn):
    cipher = AES.new(key16, AES.MODE_CBC)
    iv = b64encode(cipher.iv).decode('utf-8')

    cipherTxt = open(txtToReturn,"w+")
    
    with open(txtToCipher) as a:
        for line in a:
            line = bytes(line, 'utf-8')
            ct_bytes = cipher.encrypt(pad(line, AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            cipherTxt.write(ct)

    a.close()
    cipherTxt.close()

    return str(iv)

key = get_random_bytes(16)

print('IV ', AEScipher(key, 'prueba.txt', 'prueba.enc'))